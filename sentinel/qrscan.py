"""QR-code scam scanning (v1.1, optional).

A growing Nitro-scam variant hides the phishing URL inside a QR image
("scan to verify / claim"). This module decodes QR codes in image
attachments and returns any URLs found, which then flow through the
exact same Layer 1-3 pipeline as typed links.

Requires opencv-python-headless (requirements-optional.txt). Without
it, every function quietly returns nothing - the rest of the bot is
unaffected.
"""
import asyncio
import logging

log = logging.getLogger("sentinel.qr")

try:
    import cv2
    import numpy as np
    _AVAILABLE = True
except Exception:  # ImportError or missing system libs
    _AVAILABLE = False

IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".bmp")
MAX_BYTES = 8_000_000  # refuse to download/decode anything larger


def available() -> bool:
    return _AVAILABLE


def _decode_texts(data: bytes) -> list[str]:
    """All QR payload strings in one image (sync; run in a thread)."""
    if not _AVAILABLE:
        return []
    try:
        img = cv2.imdecode(np.frombuffer(data, dtype=np.uint8),
                           cv2.IMREAD_COLOR)
        if img is None:
            return []
        detector = cv2.QRCodeDetector()
        try:
            ok, decoded, _points, _ = detector.detectAndDecodeMulti(img)
            if ok:
                return [d for d in decoded if d]
        except Exception:
            pass
        # single-QR fallback (older cv2 builds)
        text, _pts, _ = detector.detectAndDecode(img)
        return [text] if text else []
    except Exception as exc:
        log.debug("QR decode failed: %s", exc)
        return []


async def extract_qr_urls(attachments) -> list[str]:
    """URLs encoded in QR codes inside image attachments."""
    if not _AVAILABLE:
        return []
    from sentinel import detection  # deferred: avoids any import cycle

    urls: list[str] = []
    for att in attachments or []:
        name = (getattr(att, "filename", "") or "").lower()
        if not name.endswith(IMAGE_EXTENSIONS):
            continue
        if getattr(att, "size", 0) and att.size > MAX_BYTES:
            continue
        try:
            data = await att.read()
        except Exception:
            continue
        for payload in await asyncio.to_thread(_decode_texts, data):
            found = detection.extract_urls(payload)
            if found:
                urls.extend(found)
            elif payload.startswith("http"):
                urls.append(payload)
    return urls
