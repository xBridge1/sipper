import sys
from pathlib import Path

from PIL import Image


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_IMAGE = PROJECT_ROOT / "logo" / "e4d70232-e1e2-4761-bd1b-dc88ac325f6e.png"


def main(destination):
    image = Image.open(SOURCE_IMAGE).convert("RGBA")
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    image.save(target, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main(sys.argv[1])
