
FROM ubuntu:23.10
RUN apt-get update && apt-get install -y \
    python3 \
    python3-tk \
    python3-pip \
    x11-apps \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install cryptography --break-system-packages

RUN mkdir -p /home/student/Intel/pdf-cont/

COPY script.py /home/student/Intel/pdf-cont/
COPY ps.pdf /home/student/Intel/pdf-cont/
COPY password.txt /home/student/Intel/pdf-cont/
COPY reset_tokens.txt /home/student/Intel/pdf-cont/
CMD ["python3", "/home/student/Intel/pdf-cont/script.py"]    
