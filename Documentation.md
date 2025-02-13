# SIEM Documentation

The BCCC-CIC-IDS-2017 dataset is a benchmark dataset for intrusion detection systems (IDS), developed by the Canadian Institute for Cybersecurity (CIC) in collaboration with BCCC (Big Data Cybersecurity Canada). It is designed to simulate real-world network traffic, including both benign (normal) and malicious activities.


## Attack Types

| Attack Type       | Description                                                      | How It Works                                                                                      | Impact                                                    | Detection Approach                                                   |
|------------------|------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------|
| **Botnet Ares**       | A botnet is a network of compromised devices controlled remotely by an attacker. | The Ares botnet infects devices, enabling attackers to execute Distributed Denial-of-Service (DDoS) attacks, data theft, phishing campaigns, and spam distribution. | Large-scale attacks, system compromise, and financial loss. | Anomaly detection based on unusual traffic patterns and multiple connection attempts from infected nodes. |
| **DDOS LOIT**         | LOIT (Low Orbit Ion Cannon) is a tool used for Distributed Denial-of-Service (DDoS) attacks. | Attackers flood a target server with massive amounts of junk requests, making it inaccessible.      | Server crashes, high downtime, and service disruption.     | Traffic volume monitoring and rate limiting to identify excessive requests from multiple sources.            |
| **DOS Golden Eye**    | GoldenEye is a Denial-of-Service (DoS) attack tool targeting web servers. | It sends a flood of malicious HTTP requests to exhaust server resources.                           | Website and web application unavailability.                | Request rate monitoring, signature-based detection, and behavioral analysis.                               |
| **DOS Hulk**          | HULK (HTTP Unbearable Load King) is a DoS attack that overwhelms web servers. | Generates randomized HTTP GET requests, bypassing caching mechanisms and exhausting bandwidth.     | Server crashes and denial of service to legitimate users.   | Anomaly detection on web traffic behavior and rate-limiting mechanisms.                                     |
| **DOS Slow HTTP**     | Exploits vulnerabilities in HTTP protocol by sending incomplete requests. | The server keeps connections open, waiting for completion, eventually consuming resources.          | Service slowdown or unavailability.                        | Identifying long-lived connections and applying timeouts for incomplete requests.                            |
| **DOS Slow Loris**    | A low-bandwidth DoS attack that keeps web server connections open indefinitely. | Sends partial HTTP headers without closing the connection, preventing new users from accessing the server. | Affected servers become unresponsive while appearing to be running normally. | Connection timeout settings and rate-limiting incomplete requests.                                            |
| **FTP Patator**       | A brute-force attack on the File Transfer Protocol (FTP).         | The attacker systematically tries multiple username-password combinations to gain unauthorized access. | Data breaches, malware injection, and unauthorized system control. | Failed login attempt monitoring and account lockouts after multiple failures.                               |
| **HeartBleed**        | A vulnerability in OpenSSL (CVE-2014-0160) that leaks sensitive server data. | Exploits the Heartbeat extension of OpenSSL to trick the server into sending confidential data.     | Private keys, passwords, and session tokens can be stolen. | TLS handshake validation and patching OpenSSL.                                                              |
| **PortScan**          | A reconnaissance attack to identify open ports and services running on a target system. | Attackers scan a range of ports to look for exploitable vulnerabilities.                           | Information gathering for later exploitation.              | Unusual scanning patterns (e.g., rapid connection attempts to multiple ports).                              |
| **SSH Patator**       | A brute-force attack targeting Secure Shell (SSH) logins.         | The attacker tries multiple password combinations to break into an SSH-protected server.            | Server compromise and unauthorized access.                 | Failed login monitoring and blocking IPs after excessive attempts.                                           |
| **Web Brute Force**   | A web attack where attackers guess username-password pairs to gain access. | Uses automated scripts to repeatedly try different credential combinations.                       | Account takeover, data leaks, and security breaches.        | CAPTCHA implementation, rate-limiting login attempts, and MFA (multi-factor authentication).                 |
| **Web SQL Injection** | Attackers inject malicious SQL queries into input fields to manipulate the backend database. | Bypasses authentication, exfiltrates sensitive data, and alters database contents.                  | Data theft, database corruption, or complete system takeover. | Input sanitization, prepared statements, and web application firewalls.                                     |
| **Web XSS**           | Attackers inject malicious JavaScript into web pages viewed by users. | When a victim loads the webpage, the script executes, stealing credentials or redirecting traffic. | Session hijacking, phishing attacks, and data theft.        | Input validation, escaping special characters, and Content Security Policy (CSP).                           |


## Dataset Features

---

### 1. Flow Information
| Feature             | Description                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------|
| **flow_id**         | Unique identifier for each network flow.                                                          |
| **timestamp**       | Time at which the flow was captured.                                                              |

---

### 2. Source and Destination Information
| Feature             | Description                                                                                       |
|---------------------|---------------------------------------------------------------------------------------------------|
| **src_ip**          | Source IP address of the packet sender.                                                            |
| **src_port**        | Source port number from where the packet originated.                                               |
| **dst_ip**          | Destination IP address where the packet is being sent.                                             |
| **dst_port**        | Destination port number on the receiver's end.                                                     |
| **protocol**        | Communication protocol used (e.g., TCP, UDP, ICMP).                                                |

---

### 3. Flow Duration and Packet Count
| Feature                    | Description                                                                                       |
|-----------------------------|---------------------------------------------------------------------------------------------------|
| **duration**               | Duration of the network flow in seconds.                                                           |
| **packets_count**           | Total number of packets in the flow.                                                              |
| **fwd_packets_count**       | Number of packets sent from source to destination.                                                |
| **bwd_packets_count**       | Number of packets sent from destination to source.                                                 |

---

### 4. Payload Information
| Feature                       | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| **total_payload_bytes**       | Total bytes in the payload for the flow.                                                          |
| **fwd_total_payload_bytes**   | Total payload bytes sent from source to destination.                                               |
| **bwd_total_payload_bytes**   | Total payload bytes sent from destination to source.                                               |
| **payload_bytes_max**         | Maximum payload size in a single packet.                                                          |
| **payload_bytes_min**         | Minimum payload size in a single packet.                                                          |
| **payload_bytes_mean**        | Average payload size across all packets.                                                          |
| **payload_bytes_std**         | Standard deviation of payload sizes.                                                             |
| **payload_bytes_variance**    | Variance of payload sizes.                                                                       |

---

### 5. Header Information
| Feature                          | Description                                                                                       |
|----------------------------------|---------------------------------------------------------------------------------------------------|
| **total_header_bytes**           | Total bytes used for headers in the flow.                                                          |
| **max_header_bytes**             | Maximum header size in a single packet.                                                           |
| **min_header_bytes**             | Minimum header size in a single packet.                                                           |
| **mean_header_bytes**            | Average header size across all packets.                                                           |
| **std_header_bytes**             | Standard deviation of header sizes.                                                              |

---

### 6. Segment Size Information
| Feature                       | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| **fwd_avg_segment_size**      | Average segment size sent from source to destination.                                               |
| **bwd_avg_segment_size**      | Average segment size sent from destination to source.                                               |
| **avg_segment_size**          | Overall average segment size for the flow.                                                          |

---

### 7. Window Size Information
| Feature                  | Description                                                                                       |
|---------------------------|---------------------------------------------------------------------------------------------------|
| **fwd_init_win_bytes**    | Initial window size in bytes from source to destination.                                           |
| **bwd_init_win_bytes**    | Initial window size in bytes from destination to source.                                           |

---

### 8. Active and Idle Time
| Feature               | Description                                                                                       |
|------------------------|---------------------------------------------------------------------------------------------------|
| **active_min**        | Minimum active time for the flow.                                                                  |
| **active_max**        | Maximum active time for the flow.                                                                  |
| **active_mean**       | Average active time for the flow.                                                                  |
| **active_std**        | Standard deviation of active times.                                                               |
| **idle_min**          | Minimum idle time between packets.                                                                |
| **idle_max**          | Maximum idle time between packets.                                                                |
| **idle_mean**         | Average idle time between packets.                                                                |
| **idle_std**          | Standard deviation of idle times.                                                                 |

---

### 9. Traffic Rate Information
| Feature                   | Description                                                                                       |
|----------------------------|---------------------------------------------------------------------------------------------------|
| **bytes_rate**             | Rate of bytes transferred per second.                                                             |
| **fwd_bytes_rate**         | Rate of bytes sent from source to destination.                                                     |
| **bwd_bytes_rate**         | Rate of bytes sent from destination to source.                                                     |
| **packets_rate**           | Rate of packets transferred per second.                                                           |
| **fwd_packets_rate**       | Rate of packets sent from source to destination.                                                   |
| **bwd_packets_rate**       | Rate of packets sent from destination to source.                                                   |

---

### 10. Bulk Information
| Feature                          | Description                                                                                       |
|----------------------------------|---------------------------------------------------------------------------------------------------|
| **avg_fwd_bytes_per_bulk**        | Average forward bytes per bulk transfer.                                                         |
| **avg_fwd_packets_per_bulk**      | Average forward packets per bulk transfer.                                                       |
| **avg_fwd_bulk_rate**             | Average rate of forward bulk transfers.                                                         |
| **avg_bwd_bytes_per_bulk**        | Average backward bytes per bulk transfer.                                                       |
| **avg_bwd_packets_bulk_rate**     | Average backward packets per bulk transfer.                                                     |
| **avg_bwd_bulk_rate**             | Average rate of backward bulk transfers.                                                        |

---

### 11. Flag Counts
| Feature                      | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| **fin_flag_counts**           | Count of FIN flags, indicating session termination.                                               |
| **syn_flag_counts**           | Count of SYN flags, initiating a connection.                                                      |
| **ack_flag_counts**           | Count of ACK flags, acknowledging received data.                                                  |
| **rst_flag_counts**           | Count of RST flags, resetting a connection.                                                       |
| **psh_flag_counts**           | Count of PSH flags, pushing buffered data to the receiver.                                         |
| **urg_flag_counts**           | Count of URG flags, indicating urgent data.                                                       |
| **ece_flag_counts**           | Count of ECE flags, indicating congestion.                                                        |
| **cwr_flag_counts**           | Count of CWR flags, signaling congestion window reduction.                                         |

---

### 12. Inter-Arrival Time (IAT)
| Feature                       | Description                                                                                       |
|-------------------------------|---------------------------------------------------------------------------------------------------|
| **packets_IAT_mean**          | Mean of the time between packet arrivals.                                                         |
| **packet_IAT_std**            | Standard deviation of packet inter-arrival times.                                                 |
| **packet_IAT_max**            | Maximum inter-arrival time between packets.                                                       |
| **packet_IAT_min**            | Minimum inter-arrival time between packets.                                                       |
| **packet_IAT_total**          | Total inter-arrival time for all packets.                                                         |

---

### 13. Subflow Information
| Feature                     | Description                                                                                       |
|------------------------------|---------------------------------------------------------------------------------------------------|
| **subflow_fwd_packets**      | Number of forward packets in the subflow.                                                         |
| **subflow_bwd_packets**      | Number of backward packets in the subflow.                                                        |
| **subflow_fwd_bytes**        | Number of forward bytes in the subflow.                                                           |
| **subflow_bwd_bytes**        | Number of backward bytes in the subflow.                                                          |

---

### 14. Label
| Feature    | Description                                                                                       |
|------------|---------------------------------------------------------------------------------------------------|
| **label**  | Class label indicating whether the flow is normal or an attack type.                               |
