
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io, datetime
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, make_response, flash, url_for, redirect
from flask_login import login_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from app.functions import *
import app.globals as globals
from app.models import User ,Conversations, User_Conversations, Messages, Shop, Purchase_Receipts
from app.extensions import db
from sqlalchemy import text


social = Blueprint("social",__name__, url_prefix="/social", static_folder=f"static",template_folder=f"templates")    

@social.route("/my_profile", methods=["GET","POST"])
@login_required
def my_profile():
    if request.method == 'GET':
        return render_template('profile.html')
    elif request.form.get('value') == 'add':
        return redirect(url_for("shop.add_item"))
    elif request.form.get('value') == 'up':
        return render_template('profile.html',choice='up')
    elif request.form.get('value') == 'rec':
        receipts = Purchase_Receipts.query.filter_by(user_id=current_user.user_id).all()
        return render_template('profile.html',choice='rec', rec=receipts)
    elif request.form.get('value') == 'shop':
        products = Shop.query.filter_by(owner_id=current_user.user_id).all()
        return render_template('profile.html',choice='shop', products=products)
    else:
        if request.form.get('up') == 'Submit': 
            update_info = request.form
            try:
                current_user.fname = update_info['fname']
                current_user.lname = update_info['lname']
                current_user.username = update_info['un']
                current_user.email = update_info['email']
                current_user.notes = update_info['notes']
                if update_info['pwd'] != "":
                    current_user.password = generate_password_hash(update_info['pwd'])
                db.session.commit()
            except Exception as e:
                #print(str(e))
                flash("Error updating user. Please try again, if issues persists please contact support.")
                return redirect(url_for('social.my_profile'))
            flash("User updated!")
            return redirect(url_for('social.my_profile'))



@social.route("/messages", methods=["GET","POST"],defaults={"cid":None})
@social.route("/messages/<path:cid>", methods=["GET","POST"])
@login_required
def messages(cid=None):
    if request.method == "GET":
        if cid == None:
            user_conversations = User_Conversations.query.filter_by(user_id=current_user.user_id).all()
            convo_id_list = [c.convo_id for c in user_conversations]
            convo_list = list()
            for cid in convo_id_list:
                convo = Conversations.query.filter_by(convo_id=int(cid)).first()
                participants = convo.participants.split('|')
                participants.remove(current_user.username)
                other_participant = participants[0]
                convo_list.append({"conversation_id":convo.convo_id,"other_participant":other_participant})   # ,"latest_message":latest_msg
            empty = True if convo_list == [] else False
            return render_template("messages.html", convo_list=convo_list, empty=empty)
        else:
            cur_convo = Conversations.query.filter_by(convo_id=int(cid)).first()
            tmp_participant = cur_convo.participants.split('|')
            tmp_participant.remove(current_user.username)
            other_user = tmp_participant[0]
            convo_msgs = Messages.query.filter_by(convo_id=cid).order_by(Messages.sent_time).all()
            msg_list = list()
            for msg in convo_msgs:
                sender_un = db.session.query(User.username).filter_by(user_id=msg.sender_id).first()[0]
                me = True if msg.sender_id == current_user.user_id else False
                msg_list.append({"me":me,"sender_un":sender_un,"content":msg.content,"sent_time":msg.sent_time})
            return render_template("messages.html", msgs=msg_list, other_user=other_user,cid=cid)
    else:
        if cid == None:
            flash("Error fetching conversation")
            return redirect(url_for("social.messages"))
        data = {
            "convo_id":cid,
            "sender_id":current_user.user_id,
            "content":request.form.get('msg').strip('\n'),
            "sent_time":datetime.datetime.now().strftime('%d-%m-%Y, %H:%M')
        }
        resp = send_message(data)
        if not resp:
            flash("Message failed to send")
        return redirect(url_for("social.messages",cid=cid))
        



@social.route("/user",methods=['GET','POST'],defaults={"id":None})
@social.route("/user/<path:id>",methods=['GET','POST'])
def user_profile(id):
    user = User.query.filter_by(user_id=id).first()
    if request.method == 'GET':
        if id == None:
            return redirect(url_for("social.user_profile"))
        if user == None:
            flash("Account does not exist")
            return redirect(url_for("social.user_profile"))
        return render_template("user_profile.html",user=user)
    elif request.form.get('value') == 'msg':
        return render_template('user_profile.html',choice='msg',user=user)
    elif request.form.get('value') == 'shop':
        products = Shop.query.filter_by(owner_id=id).all()
        return render_template('user_profile.html',choice='shop', products=products,user=user)
    else:
        if request.form.get('msg') == 'Submit':
            content = request.form.get('note')
            resp = profile_msg_send(content,user)
            if type(resp) == str:
                    flash(resp)
                    return redirect(url_for('social.user_profile',user=user))
            if not resp:
                flash("Unable to send message from profile. Please try again")
                return redirect(url_for('social.user_profile',user=user))
            flash("Message Sent!")
            return redirect(url_for('social.messages'))


