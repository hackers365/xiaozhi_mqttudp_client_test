import json
import sys
import paho.mqtt.client as mqtt

# hello 消息体结构
def build_hello_message():
    return {
        "type": "hello",
        "version": 3,
        "transport": "udp",
        "audio_format": {
            "format": "opus",
            "sample_rate": 16000,
            "channels": 1,
            "frame_duration": 60
        }
    }

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("MQTT 连接成功")
        # 连接成功后发布 hello 消息
        public_hello(client)
    else:
        print("连接失败，返回码:", rc)
        sys.exit(1)

def on_message(client, userdata, msg):
    print(f"收到消息: [{msg.topic}] {msg.payload.decode('utf-8')}")

def public_hello(client):
    topic = "device-server"
    message = build_hello_message()
    json_data = json.dumps(message)
    print("发布消息:", json_data)
    result = client.publish(topic, json_data, qos=0, retain=False)
    result.wait_for_publish()
    if result.is_published():
        print("发布消息成功")
    else:
        print("发布消息失败")

def main():
    broker = "mqtt.xiaozhi.me"
    port = 8883
    client_id = "GID_test@@@02_4A_7D_E3_89_BF@@@e3b0c442-98fc-4e1a-8c3d-6a5b6a5b6a5b"
    username = "eyJpcCI6IjEuMjAyLjE5My4xOTQifQ=="
    password = "Ru9zRLdD/4wrBYorxIyABtHe8EiA1hdZ4v34juJ2BUU="

    client = mqtt.Client(client_id=client_id)
    client.username_pw_set(username, password)
    client.tls_set()  # 使用 SSL 连接

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(broker, port, keepalive=60)
    client.loop_forever()

if __name__ == "__main__":
    main()
    