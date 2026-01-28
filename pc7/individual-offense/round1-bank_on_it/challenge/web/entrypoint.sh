#!/bin/bash

# Set up paths
BASE_DIR="/git"
WORK_DIR="/tmp/git_build"
REPO_DIR="$WORK_DIR/repo"

# Clean and create working directory
rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
cd "$REPO_DIR"

git config --global user.name "root"
git config --global user.email "root@trustfallbank.us"

# Init repo
git init

# First commit from init/
cp -r "$BASE_DIR/init/"* .
git add .
git commit -m "Start development"
sleep 5

# Branch to dev
git checkout -b dev

# Apply commit1, commit2, commit3
cp -r "$BASE_DIR/commit1/"* .
git add .
git commit -m "Home page"
sleep 5

cp -r "$BASE_DIR/commit2/"* .

sed -i "s/_TOKEN_/${tokenGitCode}/" ./app.py

git add .
git commit -m "Login"
sleep 5

cp -r "$BASE_DIR/commit3/"* .
git add .
git commit -m "Accounts and transactions"
sleep 5

# Merge dev back into main
git checkout master
git merge dev --no-ff -m "v1"

# Insert token in .git/config
echo -e "\n[token]\n\tvalue = ${tokenGitConfig}" >> .git/config

# Place .git in app
cp -r .git /app/.git

# Insert token in admin page
sed -i "s/_TOKEN_/${tokenAdminSession}/" /app/templates/admin.html

cd /app

echo "Wait for database to start"
/usr/bin/wait-for-it --host=database --port=3306 --timeout=30 --strict

# Start the web server
service nginx start
gunicorn app:app --bind 127.0.0.1:5000