import yaml


def load_rule(rule_path: str) -> dict:
    with open(rule_path, "r") as f:
        return yaml.safe_load(f)


print("loading rule")
print(load_rule("/Users/admin/Desktop/Termtrix-Sentinel/Termtrix-Sentinel/sentinel/rules/nginx/path_traversal.yaml"))