import logging
import configparser
import json
from phue import Bridge
from rgb_scheduler.path_utils import get_data_path

logger = logging.getLogger(__name__)


def load_hue_config(filename="config.ini"):
    config = configparser.ConfigParser()
    config.read(filename)
    hue_cfg = config["philips.hue"]
    return {
        "bridge_ip": hue_cfg.get("BridgeIp"),
        "group_name": hue_cfg.get("GroupName"),
        "group_type": hue_cfg.get("GroupType"),
        "light": hue_cfg.get("Light"),
        "daytime_scene": hue_cfg.get("DaytimeScene"),
        "nighttime_scene": hue_cfg.get("NighttimeScene"),
    }


def get_bridge(bridge_ip):
    bridge = Bridge(bridge_ip)
    try:
        bridge.connect()
    except Exception as e:
        logger.error(f"Failed to connect to Hue bridge at {bridge_ip}: {e}")
        raise
    return bridge


def get_group_id(bridge, group_name, group_type):
    for group_id, group in bridge.get_group().items():
        if group["name"] == group_name and group["type"].lower() == group_type.lower():
            return group_id
    return None


def get_scene_id(bridge, scene_name, group_id=None):
    for scene_id, scene in bridge.get_scene().items():
        if scene["name"] == scene_name:
            if group_id is None or scene.get("group") == group_id:
                return scene_id
    return None


def list_scenes_for_group(bridge, group_id):
    scenes = bridge.get_scene()
    matched_scenes = []
    for scene_id, s in scenes.items():
        if s.get("group") == group_id:
            obj = {"id": scene_id, "name": s.get("name", "")}
            matched_scenes.append(obj)
    return matched_scenes


def save_scenes_for_default_group_to_file(config_path="config.ini", output_file=None):
    if output_file is None:
        output_file = get_data_path("scenes.json")
    cfg = load_hue_config(config_path)
    bridge = get_bridge(cfg["bridge_ip"])
    group_id = get_group_id(bridge, cfg["group_name"], cfg["group_type"])
    if not group_id:
        logger.warning(
            f"Group '{cfg['group_name']}' of type '{cfg['group_type']}' not found."
        )
        return
    scenes = list_scenes_for_group(bridge, group_id)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(scenes, f, ensure_ascii=False, indent=2)
    logger.info(f"Scene data written to {output_file}")


def toggle_hue(
    bridge_ip,
    light_name,
    group_name,
    group_type,
    scene_name,
    is_nighttime: bool,
    logger=None,
):
    """
    Toggle Philips Hue lights/scenes

    Args:
        bridge_ip: IP address of the Hue bridge
        light_name: Name of the light to control (used when scene_name is "Off")
        group_name: Name of the group for scene activation
        group_type: Type of the group
        scene_name: Name of the scene to activate, or "Off" to turn off lights
        is_nighttime: If True, applies nighttime behavior; if False, applies daytime behavior
        logger: Logger instance
    """
    logger = logger or logging.getLogger(__name__)
    bridge = get_bridge(bridge_ip)

    if scene_name.lower() == "off":
        # Turn off the specified light
        logger.info(f"Turning off Hue light: {light_name}")
        bridge.set_light(light_name, "on", False)
    else:
        # Activate the specified scene
        group_id = get_group_id(bridge, group_name, group_type)
        scene_id = get_scene_id(bridge, scene_name, group_id)

        if not group_id or not scene_id:
            if not group_id:
                logger.warning(f"Group '{group_name}' (type: {group_type}) not found")
            if not scene_id:
                logger.warning(
                    f"Scene '{scene_name}' not found for group '{group_name}'"
                )
            logger.info(f"Fallback: Turning on Hue light: {light_name}")
            bridge.set_light(light_name, "on", True)
        else:
            logger.info(f"Activating Hue scene '{scene_name}' in group '{group_name}'")
            bridge.activate_scene(int(group_id), scene_id)


def set_manual_hue_scene(
    bridge_ip, group_name, group_type, scene_name, light_name, logger=None
):
    """
    Set a specific Hue scene manually or turn off lights

    Args:
        bridge_ip: IP address of the Hue bridge
        group_name: Name of the group for scene activation
        group_type: Type of the group
        scene_name: Name of the scene to activate, or "Off" to turn off lights
        light_name: Name of the light to turn off (used when scene_name is "Off")
        logger: Logger instance
    """
    logger = logger or logging.getLogger(__name__)

    logger.info(f"Setting manual Hue scene: '{scene_name}'")
    toggle_hue(
        bridge_ip,
        light_name,
        group_name,
        group_type,
        scene_name,
        is_nighttime=True,  # Doesn't affect the logic when scene_name is provided
        logger=logger,
    )
