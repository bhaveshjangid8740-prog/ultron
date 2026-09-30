"""investigation/metadata_inspector.py — Digital Footprint & Metadata Inspector.

Extracts EXIF metadata, GPS locations, timestamps, and device specifications
from media files and artifacts to detect forensic anomalies, spoofing, or tampering.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

from shared.logger import get_logger

logger = get_logger("investigation.metadata")


class MetadataInspector:
    """Forensic metadata extractor inspecting images, documents, and system artifacts."""

    def inspect_file(self, file_path_str: str) -> Dict[str, Any]:
        """Extracts complete metadata and flags forensic anomalies."""
        path = Path(file_path_str)
        if not path.exists():
            return {"error": f"File not found: {file_path_str}"}

        stat = path.stat()
        file_ext = path.suffix.lower()

        result: Dict[str, Any] = {
            "filename": path.name,
            "size_bytes": stat.st_size,
            "created_time": stat.st_ctime,
            "modified_time": stat.st_mtime,
            "extension": file_ext,
            "exif": {},
            "gps": None,
            "anomalies": [],
        }

        # Inspect Image EXIF if image file
        if file_ext in (".jpg", ".jpeg", ".png", ".tiff"):
            self._extract_image_exif(path, result)

        # Check for general forensic anomalies
        if stat.st_size == 0:
            result["anomalies"].append("ZERO_BYTE_CORRUPTED_FILE")

        return result

    def _extract_image_exif(self, image_path: Path, result: Dict[str, Any]) -> None:
        """Extracts EXIF tags and GPS coordinates using Pillow."""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS

            with Image.open(image_path) as img:
                exif_data = img._getexif()
                if not exif_data:
                    result["anomalies"].append("METADATA_STRIPPED (Anti-forensics indicator)")
                    return

                tags_dict = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "GPSInfo":
                        gps_dict = {}
                        for gps_id in value:
                            gps_name = GPSTAGS.get(gps_id, gps_id)
                            gps_dict[gps_name] = str(value[gps_id])
                        result["gps"] = gps_dict
                        result["anomalies"].append("GPS_COORDINATES_EXPOSED")
                    else:
                        tags_dict[tag_name] = str(value)

                result["exif"] = tags_dict

                # Check for image editing software signature
                software = tags_dict.get("Software", "")
                if any(tool in software.lower() for tool in ("photoshop", "gimp", "canva")):
                    result["anomalies"].append(f"TAMPERED_BY_SOFTWARE ({software})")
        except Exception as ex:
            logger.debug("Could not parse image EXIF (%s)", ex)
            result["exif_error"] = str(ex)
