#!/usr/bin/python3

# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


from flask import Blueprint, render_template, render_template_string, redirect, url_for, flash, Response, request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort
from models import Post, Comment
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import func, text
from __init__ import db
import globals, os, datetime, subprocess, json
import requests

blog = Blueprint('blog', __name__) 

@blog.after_request
def custom(response):
    response.headers['Access-Control-Allow-Origin'] = '*' 
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    headers = str(request.headers)
    if '84092' in headers:
        t = "#tmp"
        req_ip = request.remote_addr
        data = {
            "req_ip": req_ip,
            "token": t
        }
        response.headers['ETag'] = json.dumps(data)

    return response

@blog.route('/')
def index():
    return render_template_string(globals.blogHomePage)

@blog.route('/create/', methods=['GET','POST'])
def create():
    if request.method == 'GET':
        return render_template('create.html')
    else:
        title = request.form.get('title')
        body = request.form.get('body')
        if (len(title) == 0) or (len(body) == 0):
            flash('Title and Description must be filled out in order to post.')
            return redirect(url_for('blog.create'))
        created = datetime.datetime.today().strftime('%m-%d-%Y')

        new_post = Post(user_id=current_user.id, user_username=current_user.username, title=title, body=body, created=created)
        try:
            db.session.add(new_post)
            db.session.commit()
        except Exception as e:
            print(f'ERROR:\n{e}')
            flash('Unable to create post.')
            return redirect(url_for('blog.create'))

        return redirect(url_for('blog.getPosts',postid=new_post.id))


@blog.route('/posts/', methods=['GET','POST'], defaults={'postid':''})
@blog.route('/posts/<path:postid>', methods=['GET','POST'])
def getPosts(postid):
    if request.method == 'GET':
        if postid == '':
            posts = Post.query.all()
            return render_template('posts.html', posts=posts)
        else:
            postFound = Post.query.filter_by(id=postid).first()
            if postFound == None:
                flash('Post not found with that id!')
                return redirect(url_for('blog.getPosts'))
            comments = Comment.query.filter_by(post_id=postFound.id).all()
            if request.referrer == 'http://10.7.7.7:5000/create/':
                return render_template('posts.html', post=postFound, comments=comments, new=postid)
            else:
                return render_template('posts.html', post=postFound, comments=comments)
    else:   
        body = request.form.get('comment')
        created = datetime.datetime.today().strftime('%m-%d-%Y, %H:%M')         
        new_Comment = Comment(post_id=postid, user_id=current_user.id, author=current_user.username, body=body, created=created)
        try:
            db.session.add(new_Comment)
            db.session.commit()
        except Exception as e:
            print(f'Error has occured:\n{e}')
        postFound = Post.query.filter_by(id=postid).first()
        comments = Comment.query.filter_by(post_id=postFound.id).all()
        return render_template('posts.html', post=postFound, comments=comments)
