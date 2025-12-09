from fastapi import FastAPI, File, UploadFile
from pathlib import Path
import os
from fastapi.responses import JSONResponse

from file import ALLOWED_FILE_TYPES, MAX_FILE_SIZE_BYTES, file_response, save_uploaded_file


app = FastAPI()

# Define the absolute path based on the script location
BASE_DIR = Path(__file__).resolve().parent 
UPLOAD_DIR: Path = BASE_DIR / "uploads"
UPLOAD_DIR_STR: str = str(UPLOAD_DIR) # Use string version for function compatibility

# Ensure the directory exists immediately on startup
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@app.post("/upload")
async def upload_document(file: UploadFile = File(...)):
    """
    Endpoint to handle file uploads.
    """
    try:
        saved_path = await save_uploaded_file(
            file=file,
            dest_folder=UPLOAD_DIR_STR,
            allowed_types=ALLOWED_FILE_TYPES,
            max_size_bytes=MAX_FILE_SIZE_BYTES
        )
        
        # Return the filename (relative to the upload dir)
        filename = os.path.basename(saved_path)
        
        return JSONResponse(
            content={
                "message": "File uploaded successfully",
                "filename": filename,
                "path": f"/files/{filename}"
            },
            status_code=201
        )
    except Exception as e:
        # In a real app, you might want to log the error here
        raise e

@app.get("/files/{filename}")
def download_file(filename: str):
    """
    Endpoint to retrieve files securely.
    """
    # Construct the full path
    # strictly joining paths to prevent traversal
    file_path = os.path.join(UPLOAD_DIR_STR, filename)
    
    # Validate and return
    return file_response(file_path,UPLOAD_DIR_STR)

if __name__ == "__main__":
    import uvicorn
    # Run the app
    uvicorn.run(app, host="0.0.0.0", port=8000)
