
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import sys, os, datetime, random, string
from flask_login import logout_user, current_user
from flask import redirect, url_for, flash, session, request
from app.extensions import db
from app.models import User ,Conversations, User_Conversations, Messages, Shop, Purchase_Receipts
from sqlalchemy import text


def send_message(data):
    new_msg = Messages(convo_id=data['convo_id'],sender_id=data['sender_id'],content=data['content'],sent_time=data['sent_time'])
    try:
        db.session.add(new_msg)
        db.session.commit()
    except Exception as e:
        print(f"Error occurred when attempting add new msg.\n{str(e)}")
        return False
    else:
        return True


def profile_msg_send(content, user):
    expr = text(f"select * from Conversations where participants='{current_user.username}|{user.username}' or participants='{user.username}|{current_user.username}'")
    convo_check = db.session.execute(expr).fetchone()
    created = datetime.datetime.now().strftime('%d-%m-%Y, %H:%M')
    if convo_check == None:
        new_convo = Conversations(participants=f'{current_user.username}|{user.username}',created=created)
        try:
            db.session.add(new_convo)
            db.session.commit()
        except Exception as e:
            print(f"Error: Could not create new Conversation for users {user.username} & {current_user.username}.\nError Message:\t{str(e)}")
            return 'Error: Could not create conversation. Please try again.'
        
        current_convo = Conversations.query.filter_by(participants=f'{current_user.username}|{user.username}').first()
        for u in [user, current_user]:
            new_user_convo = User_Conversations(user_id=u.user_id,convo_id=current_convo.convo_id)
            try:
                db.session.add(new_user_convo)
                db.session.commit()
            except Exception as e:
                print(f"Error: Could not add user_conversation to DB for user {u.username}.\n{str(e)}")
                return "Error: Could not send message. Please try again."
        data = {
            "convo_id":current_convo.convo_id,
            "sender_id":current_user.user_id,
            "content":content,
            "sent_time":created
        }
        return send_message(data)
    else:
        data = {
            "convo_id":convo_check.convo_id,
            "sender_id":current_user.user_id,
            "content":content,
            "sent_time":created
        }
        return send_message(data)


def search_query(search_type, search_str):
    sql_expr = {
        "get": {
            "user": "user_id,username,role",
            "shop": "item_id,owner_id,category_id,name,desc,price"
        },
        "query": {
            "user": "(fname || ' ' || lname || ' ' || username)",
            "shop": "(name || ' ' || desc || ' ' || price)"
        }
    }
    if (search_str == None) or (search_str == ""):
        expr = text(f"select {sql_expr['get'][search_type]} from {search_type};")
        all_records = db.session.execute(expr).fetchall()
        rec_dict = dict(all_records)
        return rec_dict
    else:
        expr = text(f"select {sql_expr['get'][search_type]} from {search_type} where {sql_expr['query'][search_type]} like '%{search_str}%';")
        result = db.session.execute(expr).fetchall()       
        result_dict = dict()
        for counter,res in enumerate(result,start=1):
            result_dict[str(counter)] = dict(res)
        return result_dict

def cleanup_category_db(category_id):
    expr = text(f"delete from Categories where category_id={category_id}")
    try:
        db.session.execute(expr)
        db.session.commit()
    except Exception as e:
        print(f"ERROR Removing Category.\n{str(e)}")
    else:
        print("Successfully removed unused category")
    return

def logout():
    logout_user()
    session.clear()
    return redirect(url_for("main.home"))


