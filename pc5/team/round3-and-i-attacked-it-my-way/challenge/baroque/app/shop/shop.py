
# Copyright 2024 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.


import subprocess, io
from flask import Blueprint, render_template_string, render_template, request, Response, current_app, send_file, make_response, flash, url_for, redirect, session
from flask_login import login_user, current_user, login_required
from app.functions import *
from sqlalchemy import text
from app.models import *
from functools import wraps
from app.extensions import db
import app.globals as globals


shop = Blueprint("shop",__name__,url_prefix="/shop", static_folder=f"static",template_folder=f"templates")    

@shop.route("/", methods=['GET','POST'], defaults={'category':None,'item_id':None})
@shop.route("/<path:category>/", methods=['GET','POST'], defaults={'item_id':None})
@shop.route("/<path:category>/<path:item_id>", methods=['GET','POST'])
def browse(category, item_id):
    if request.method == 'GET':
        all_categories = Categories.get_dict()
        if (category == None) and (item_id == None):
            items = Shop.query.all()
            return render_template("shop.html", all_categories=all_categories, items=items)
        elif (item_id == None):
            cur_category = db.session.execute(text(f"select category_id,category from Categories where category='{category}';")).fetchall()
            if cur_category == None:
                flash("Category not found, please view side navigation bar for categories available")
                return redirect(url_for('shop.browse'))
            category_id = db.session.execute(text(f"""select category_id,category from Categories where category="{category}" """)).fetchone()
            items = Shop.query.filter_by(category_id=category_id[0]).all()
            return render_template("shop.html", all_categories=all_categories, items=items, cur_category=cur_category)
        else:
            cur_category = Categories.query.filter_by(category=category).first()
            if cur_category == None:
                flash("Category not found, please view side navigation bar for categories available")
                return redirect(url_for('shop.browse'))
            cur_item = Shop.query.filter_by(item_id=item_id).first()
            if cur_item == None:
                flash("Product not found, please use the search bar or browse selection to find available items.")
                return redirect(url_for('shop.browse'))
            seller = User.query.filter_by(user_id=cur_item.owner_id).first()
            return render_template("shop.html", all_categories=all_categories, cur_item=cur_item, seller=seller)
            


@shop.route("/cart", methods=['GET','POST'])
def cart():
    if request.method == "POST":
        req_data = request.form
        item_to_add = Shop.query.filter_by(item_id=req_data['item_id']).first()
        if item_to_add == None:
            flash("Error adding item to cart, item missing or removed from shop.")
            return redirect(url_for('shop.cart'))
        if str(item_to_add.item_id) in list(session['cart'].keys()):
            session['cart'][str(item_to_add.item_id)] += int(req_data['quantity'])
        else:
            session['cart'][str(item_to_add.item_id)] = int(req_data['quantity'])
        session.modified = True
    
    cur_cart = dict()
    total_tracker = 0
    for item_id,quantity in session['cart'].items():
        cur_item = Shop.query.filter_by(item_id=item_id).first()
        item_total = int(quantity) * int(cur_item.price[1:])
        total_tracker += item_total
        cur_cart[item_id] = {
            "name":cur_item.name,
            "quantity":str(quantity),
            "price": cur_item.price,
            "total": f"${str(item_total)}"
        }
    cur_cart['total'] = f"${str(total_tracker)}"
    return render_template('cart.html',cart=cur_cart)

@shop.route("/add_item",methods=["GET","POST"])
@login_required
def add_item():
    if request.method == "GET":
        return render_template("add_item.html")
    else:
        item_data = request.form
        check_category = Categories.query.filter_by(category=item_data['category']).first()
        if check_category == None:
            new_category = Categories(category=item_data['category'].strip(' '))
            try:
                db.session.add(new_category)
                db.session.commit()
            except Exception as e:
                print(f"ERROR Adding Category:\t{str(e)}")
                flash("Unable to add new category")
                return redirect(url_for("shop.add_item"))
        new_cate = Categories.query.filter_by(category=item_data['category']).first()
        tmp_price = item_data['price'].lstrip()
        price = tmp_price if tmp_price[0] == '$' else f"${tmp_price}"

        new_item = Shop(owner_id=current_user.user_id,category_id=new_cate.category_id,name=item_data['name'],desc=item_data['desc'],price=price)
        try:
            db.session.add(new_item)
            db.session.commit()
        except Exception as e:
            print(f"ERROR Adding Item:\t{str(e)}")
            flash("Unable to list item.")
            return redirect(url_for("shop.add_item"))

        flash("Item Listed!")
        item = Shop.query.filter_by(owner_id=current_user.user_id,name=item_data['name']).first()
        return redirect(url_for("shop.browse")+f"{item_data['category']}/{item.item_id}")
    

