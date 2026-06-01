#!/bin/bash
echo -e "git_user: test-user\ngit_pass: gityourmoneyup\n$TOKEN1" > /vault.yml
ansible-vault encrypt /vault.yml --vault-password-file /pass.txt
mv /vault.yml /git/commit2/vault.yml
rm -f /pass.txt
unset TOKEN1

# Set up paths
BASE_DIR="/git"
WORK_DIR="/tmp/git_build"
REPO_DIR="$WORK_DIR/repo"

# Clean and create working directory
rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"

#dos2unix
dos2unix /git/*/*

# Init repo
git init
#git config --global user.name "user1"
git config --global user.email "user1@devops.local"

git symbolic-ref HEAD refs/heads/master

# First commit from init/
cp -r "$BASE_DIR/init/"* .
git add .
git commit -m "Base Inventory File"
sleep 5

# Branch to dev
git checkout -b dev

# Apply commit1, commit2, commit3, commit4
cp -r "$BASE_DIR/commit1/"* .
git add .
git commit -m "Add Fileservers to Inventory"
sleep 5

cp -r "$BASE_DIR/commit2/"* .

git add .
git commit -m "Update Inventory and Add vault"
sleep 5

cp -r "$BASE_DIR/commit3/"* .
git add .
git commit -m "Update Inventory and Add Playbook"
sleep 5

cp -r "$BASE_DIR/commit4/"* .
git add .
git commit -m "Update Playbook"
sleep 5

# Merge dev back into main
git checkout master
git merge dev --no-ff -m "DevOps Version1"

# Place .git in backups
cp -r .git /home/user1/backups/.git
#cp -a $REPO_DIR /home/user1/backups/
chown -R user1:user1 /home/user1/backups/
rm -rf $WORK_DIR
rm -rf $BASE_DIR
