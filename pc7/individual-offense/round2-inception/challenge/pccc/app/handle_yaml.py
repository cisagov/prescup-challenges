import logging
import sys
import yaml
from flask import json

logging.basicConfig(
    filename="/app/yamlLog.txt",
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def validate_game_schema(parsed):
    if not isinstance(parsed, dict) or "game" not in parsed:
        return False, "Missing top-level 'game' key"

    game = parsed["game"]
    required_game_keys = ["title", "cover", "map", "challenges"]
    for key in required_game_keys:
        if key not in game:
            return False, f"Missing game.{key}"
    
    if not isinstance(game["challenges"], list) or len(game["challenges"]) == 0:
        return False, "game.challenges must be a non-empty list"

    for i, challenge in enumerate(game["challenges"]):
        for field in ["name", "markdown", "point", "questions"]:
            if field not in challenge:
                return False, f"Challenge[{i}] missing field: {field}"
        
        point = challenge["point"]
        for coord in ["x", "y", "r"]:
            if coord not in point or not isinstance(point[coord], (int, float)):
                return False, f"Challenge[{i}].point.{coord} missing or not a number"

        if not isinstance(challenge["questions"], list) or len(challenge["questions"]) == 0:
            return False, f"Challenge[{i}].questions must be a non-empty list"

        for j, question in enumerate(challenge["questions"]):
            if "text" not in question or "points" not in question:
                return False, f"Challenge[{i}].questions[{j}] missing 'text' or 'points'"
            if not isinstance(question["points"], int):
                return False, f"Challenge[{i}].questions[{j}].points must be int"

    return True, "Valid schema"

def main():
    try:
        # INTENTIONALLY UNSAFE: executes YAML tags like !!python/object/apply
        with open("/app/game.yml", "r") as f: 
            parsed = yaml.load(f.read(), Loader=yaml.UnsafeLoader)
        success, message = validate_game_schema(parsed)
        if success:
            # Save to json file, return code 0 with message
            with open("/app/game.json", "w") as f:
                f.write(json.dumps(parsed))
            return 0, message
        else:
            # Return code -1 with message
            return 1, message
    except Exception as e:
        logging.error(f"YAML parse error: {e}")
        return 1, "The YAML file could not be parsed due to an unexpected error."
    # Return code -1 with message
    
if __name__ == "__main__":
    code, message = main()
    print(message)
    sys.exit(code)