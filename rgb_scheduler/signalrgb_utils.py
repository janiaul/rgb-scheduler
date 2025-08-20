import os
import json
import subprocess
import logging
from html.parser import HTMLParser
from rgb_scheduler.path_utils import get_data_path

logger = logging.getLogger(__name__)


class EffectHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = None
        self.description = None

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            attrs_dict = dict(attrs)
            if "description" in attrs_dict:
                self.description = attrs_dict["description"]
            elif attrs_dict.get("name", "").lower() == "description":
                self.description = attrs_dict.get("content")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = data.strip()


def get_signalrgb_effect_url(effect_name: str) -> str:
    """Convert effect name to SignalRGB protocol URL format."""
    return effect_name.replace(" ", "%20")


def apply_signalrgb_effect(effect_name: str, logger=None):
    """Launches the SignalRGB effect via protocol URL."""
    logger = logger or logging.getLogger(__name__)
    effect_url = get_signalrgb_effect_url(effect_name)
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        subprocess.Popen(
            [
                "cmd",
                "/c",
                f"start /min signalrgb://effect/apply/{effect_url}?-silentlaunch-",
            ],
            shell=True,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        logger.info(f"Applied SignalRGB effect: {effect_name}")
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error when applying SignalRGB effect: {e}")
    except Exception as e:
        logger.error(f"Error applying SignalRGB effect: {e}")


def get_effects_dir():
    """Get the default SignalRGB effects directory."""
    localappdata = os.environ.get("LOCALAPPDATA")
    if not localappdata:
        raise RuntimeError("LOCALAPPDATA environment variable not set.")
    effects_dir = os.path.join(
        localappdata, "WhirlwindFX", "SignalRGB", "cache", "effects"
    )
    if not os.path.isdir(effects_dir):
        raise FileNotFoundError(f"Effects directory does not exist: {effects_dir}")
    return effects_dir


def get_signalrgb_effects(effects_dir=None):
    """Parse all available SignalRGB effects in the effects directory."""
    if effects_dir is None:
        effects_dir = get_effects_dir()
    effects = []
    for effect_id in os.listdir(effects_dir):
        effect_path = os.path.join(effects_dir, effect_id)
        html_file = os.path.join(effect_path, "effect.html")
        if os.path.isdir(effect_path) and os.path.isfile(html_file):
            with open(html_file, "r", encoding="utf-8") as f:
                html = f.read()
            parser = EffectHTMLParser()
            parser.feed(html)
            effects.append(
                {
                    "id": effect_id,
                    "name": parser.title or "(no title found)",
                    "description": parser.description or "(no description found)",
                }
            )
    return effects


def save_signalrgb_effects_to_file(output_file=None, effects_dir=None):
    """Parse effects and save the list to a JSON file in the data directory."""
    if output_file is None:
        output_file = get_data_path("effects.json")
    effects = get_signalrgb_effects(effects_dir)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(effects, f, indent=2, ensure_ascii=False)
    logger.info(f"Effect data written to {output_file}")
    return output_file
