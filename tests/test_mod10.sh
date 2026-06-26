#!/bin/bash

for i in {1..10}
do
  echo "Jan 25 12:00:0$i server sshd[1000]: Failed password for fakeuser from 1.2.3.10 port 22" | sudo tee -a /var/log/secure
done