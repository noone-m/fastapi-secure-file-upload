# FastAPI Secure File Upload ⚡

Production-ready, fully asynchronous file upload & download implementation for FastAPI with zero-trust security.

Most FastAPI file upload tutorials are insecure or block the event loop. This repo fixes that.

## Features

- Fully asynchronous (aiofiles + asyncio)
- Real MIME type detection using libmagic (ignores fake Content-Type headers)
- Streaming size enforcement (10 MB default, configurable)
- Atomic file writes (temp → rename, no partial/corrupted files)
- UUID + prefix filenames (no collisions or overwrites)
- Path traversal protection when serving files
- Comprehensive logging (security events, rejections, errors)
- Clean, reusable functions + minimal working example

Perfect for document management, avatars, PDFs, images, etc.

## Why this matters

| Problem                          | Naive Approach                         | This Solution                                  |
|----------------------------------|----------------------------------------|------------------------------------------------|
| Blocking event loop              | `shutil.copyfileobj()`                 | `aiofiles` + chunked async streaming           |
| Fake file types                  | Trust `Content-Type` header            | `python-magic` on actual bytes                 |
| DoS via huge files               | No limit or check after full read      | Enforced during streaming → instant 413        |
| Path traversal on download       | `open(filename)`                       | `Path.resolve()` + `is_relative_to()` check    |
| Partial/corrupted uploads        | Direct write                           | Temp file + atomic `os.replace`                |

## Quick Start

```bash
git clone https://github.com/yourname/fastapi-secure-file-upload.git
cd fastapi-secure-file-upload
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Blog Post

Full explanation:

https://noone-m.github.io/)2025-11-24-fastapi-file-upload/

## License

MIT — feel free to use in commercial projects.

⭐ Star this repo if you found it useful.
