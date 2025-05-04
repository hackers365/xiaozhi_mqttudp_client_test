package main

import mqtt "github.com/eclipse/paho.mqtt.golang"

type MqttClient struct {
	instance     mqtt.Client
	ClientId     string
	Username     string
	Password     string
	Endpoint     string
	PublishTopic string
	OnMessage    mqtt.MessageHandler
}

func NewMqttClient(clientId, username, password, endpoint, publishTopic string, OnMessage mqtt.MessageHandler) *MqttClient {
	return &MqttClient{
		ClientId:     clientId,
		Username:     username,
		Password:     password,
		Endpoint:     endpoint,
		PublishTopic: publishTopic,
		OnMessage:    OnMessage,
	}
}

func (m *MqttClient) Connect() error {
	opts := mqtt.NewClientOptions().AddBroker(m.Endpoint).SetClientID(m.ClientId)
	opts.SetUsername(m.Username)
	opts.SetPassword(m.Password)

	instance := mqtt.NewClient(opts)
	if token := instance.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}
	m.instance = instance
	return nil
}

func (m *MqttClient) Publish(topic string, payload []byte) error {
	token := m.instance.Publish(topic, 0, false, payload)
	token.Wait()
	if token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (m *MqttClient) Subscribe(topic string, callback mqtt.MessageHandler) error {
	token := m.instance.Subscribe(topic, 0, callback)
	token.Wait()
	return token.Error()
}
