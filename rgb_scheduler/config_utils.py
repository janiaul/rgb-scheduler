import configparser


def load_config(config_path):
    config = configparser.ConfigParser()
    config.read(config_path)
    return config


def get_location_info(config):
    loc = config["location.info"]
    return {
        "name": loc.get("Name"),
        "region": loc.get("Region"),
        "timezone": loc.get("Timezone"),
        "latitude": float(loc.get("Latitude")),
        "longitude": float(loc.get("Longitude")),
    }


def get_signalrgb_info(config):
    rgb = config["signal.rgb"]
    return {
        "daytime_effect": rgb.get("DaytimeEffect"),
        "nighttime_effect": rgb.get("NighttimeEffect"),
    }


def get_philips_hue_info(config):
    hue = config["philips.hue"]
    return {
        "bridge_ip": hue.get("BridgeIp"),
        "group_name": hue.get("GroupName"),
        "group_type": hue.get("GroupType"),
        "light_name": hue.get("Light"),
        "daytime_scene": hue.get("DaytimeScene"),
        "nighttime_scene": hue.get("NighttimeScene"),
    }
