import asyncio
import logging 
from typing import Dict, Optional
from uuid import uuid4
import aiofiles
from fastapi import UploadFile, HTTPException
from pathlib import Path
import os
import magic
from fastapi.responses import FileResponse

logger = logging.getLogger(__name__)

ALLOWED_FILE_TYPES = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/pjpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/tiff": ".tif",
}

MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
CHUNK_SIZE = 64 * 1024 # 64KB

async def save_uploaded_file(
    file: UploadFile,
    dest_folder: str,
    filename_prefix: str = "",
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
    allowed_types: Optional[Dict[str, str]] = None,
    ensure_unique: bool = True,
) -> str:
    """
    Securely save an uploaded file with strict validation and atomic writing.

    Performs the following security-critical checks and operations:
    - Real MIME type detection using libmagic (ignores client Content-Type header)
    - Enforces maximum file size during streaming (prevents DoS via large uploads)
    - Writes to a temporary file then atomically renames to final path
    - Generates cryptographically safe unique filenames when requested
    - Comprehensive logging at appropriate levels (INFO/WARNING/ERROR)

    Args:
        file: FastAPI UploadFile object from request
        dest_folder: Target directory where the file will be stored
        filename_prefix: Optional prefix added to the generated filename
        max_size_bytes: Maximum allowed size in bytes (default: 10 MB)
        allowed_types: Dict mapping allowed MIME types → file extensions.
                       Uses module-level ALLOWED_FILE_TYPES if None.
        ensure_unique: If True (default), appends a UUID to prevent collisions
                       and overwrites. Set to False only if caller guarantees uniqueness.

    Returns:
        str: Absolute path to the successfully saved file

    Raises:
        HTTPException:
            - 400: Invalid MIME type or unsupported content
            - 413: File exceeds size limit
            - 500: Server error (disk, permissions, unexpected I/O issues)

    Note:
        The uploaded file is always closed, and temporary files are cleaned up
        even if an exception occurs.
    """

    # Log the attempt (INFO)
    logger.info("Starting upload for file: %s (Content-Type header: %s)", 
                file.filename, file.content_type)
    
    # Load global types if not passed
    if allowed_types is None:
        allowed_types = ALLOWED_FILE_TYPES

    # --- Step 1: Real MIME validation ---
    try:
        header = await file.read(2048)
        mime = magic.Magic(mime=True).from_buffer(header)
        await file.seek(0)
    except Exception:
        # Log unexpected read errors (ERROR)
        logger.exception("Failed to read file header for MIME detection: %s", file.filename)
        raise HTTPException(status_code=500, detail="Internal server error during validation")

    if mime not in allowed_types:
        # Log the rejection (WARNING) - Good for security auditing
        logger.warning("Upload rejected. Detected MIME: '%s'. Allowed: %s", mime, allowed_types.keys())
        await file.close()
        raise HTTPException(status_code=400, detail="Invalid or unsupported file content")

    extension = allowed_types[mime]
    logger.debug("MIME detected: %s. Using extension: %s", mime, extension)

    # --- Step 2: Directory handling ---
    dest_dir = Path(dest_folder)
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.error("Could not create destination directory: %s", dest_dir)
        raise HTTPException(status_code=500, detail="Server configuration error")

    # --- Step 3: Unique filenames ---
    if ensure_unique:
        base_name = f"{filename_prefix}{uuid4().hex}{extension}"
    else:
        base_name = f"{filename_prefix}{extension}"

    final_path = dest_dir / base_name
    tmp_path = dest_dir / f".tmp_{uuid4().hex}_{base_name}"

    try:
        total_size = 0
        async with aiofiles.open(tmp_path, "wb") as out_f:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break

                total_size += len(chunk)
                if total_size > max_size_bytes:
                    # Log size violation (WARNING)
                    logger.warning("File %s exceeded size limit. Size: %s bytes", file.filename, total_size)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Max allowed is {max_size_bytes} bytes.",
                    )
                await out_f.write(chunk)

        # --- Step 4: Atomic rename ---
        await asyncio.to_thread(os.replace, tmp_path, final_path)
        
        # Log Success (INFO)
        logger.info("Successfully saved file: %s -> %s", file.filename, final_path)
        return str(final_path)

    except HTTPException:
        raise # Re-raise HTTP exceptions so FastAPI handles them
    except Exception as e:
        # Catch unexpected I/O errors (ERROR)
        logger.exception("Unexpected error saving file %s", file.filename)
        raise HTTPException(status_code=500, detail="File upload failed")
    
    finally:
        # Cleanup logic remains the same...
        await file.close()
        try:
            if tmp_path.exists():
                tmp_path.unlink()
                logger.debug("Cleaned up temporary file: %s", tmp_path)
        except Exception:
            logger.warning("Failed to cleanup temp file: %s", tmp_path)


def file_response(file_path: str, base_dir: str) -> FileResponse:
    """
    Securely serve a previously uploaded file with path traversal protection.

    Validates that the requested path:
    - Resolves to a real file inside the allowed base directory
    - Has an extension present in the global allow-list
    - Does not attempt directory traversal

    Intended to be used only with files previously saved by save_uploaded_file().

    Args:
        file_path: Raw path (or filename) as received from the client/route
        base_dir: Absolute path to the directory that contains allowed uploads

    Returns:
        FileResponse: FastAPI response that streams the file with correct headers

    Raises:
        HTTPException:
            - 404: File not found or path traversal attempt detected
            - 400: File has a disallowed extension

    Security:
        Logs path traversal attempts at ERROR level for security monitoring.
    """

    resolved_path = Path(file_path).resolve()
    base_dir_resolved = Path(base_dir).resolve()

    # Security: Path Traversal
    if not resolved_path.is_relative_to(base_dir_resolved):
        # SECURITY ALERT (CRITICAL or ERROR)
        # This implies someone is trying to hack your server (e.g. asking for ../../../etc/passwd)
        logger.error("SECURITY: Path traversal attempt detected! Requested: %s, Base: %s", file_path, base_dir)
        raise HTTPException(status_code=404, detail="File not found")
    
    if not resolved_path.exists():
        logger.info("File requested but not found: %s", resolved_path)
        raise HTTPException(status_code=404, detail="File not found")
    
    ext = resolved_path.suffix.lower()
    if ext not in ALLOWED_FILE_TYPES.values():
        logger.warning("File requested with blocked extension: %s", ext)
        raise HTTPException(status_code=400, detail="File type not allowed")

    return FileResponse(str(resolved_path))