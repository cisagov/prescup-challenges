#!/bin/bash
ssh -o StrictHostKeyChecking=no root@ubuntu1 'rm -rf /uploads/*'
scp -o StrictHostKeyChecking=no /app/uploads/* root@ubuntu1:/uploads/
ssh -o StrictHostKeyChecking=no root@ubuntu1 'echo 6470e394cbf6dab6a91682cc8585059b > /tmp/6470e394cbf6dab6a91682cc8585059b'
