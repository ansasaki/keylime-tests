import os
import toml

async def execute(event):
    if event.get("type") != "revocation":
        return

    event_uuid = event.get("agent_id", "my")
    event_ip = event.get("event_ip", "my")

    with open("/etc/keylime/agent.conf", "r") as f:
        my_uuid = toml.load(f)["agent"]["uuid"].strip('\"')
        print("A node in the network has been compromised:", event_ip)
        print("my UUID: %s, event UUID: %s" % (my_uuid, event_uuid))

    # is this revocation meant for me?
    if my_uuid == event_uuid:
        os.remove("/var/tmp/test_payload_file")
