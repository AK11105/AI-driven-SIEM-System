## Steps

### Start Kafka
```bash
docker-compose up -d
```

### Install Filebeat : [Link](https://www.elastic.co/docs/reference/beats/filebeat/setup-repositories)

### Start Filebeat
```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

### Edit the **filebeat.yml** 
```bash
vim /etc/filebeat/filebeat.yml
```

### Test the **config** and **output**
```bash
sudo filebeat test config
sudo filebeat test output
```

### Run the **log_consumer** to check that the logs are receiving
```bash
python3 log_consumer.py
```

### Verify uisng **kafka**
1. Access the Kafka container
```bash
docker ps
docker exec -it <kafka_container_name> bash
```

2. Access the Kafka container
inside container
```bash
kafka-console-consumer --bootstrap-server localhost:9092 --topic system-logs --from-beginning
```