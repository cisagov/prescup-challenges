const express = require('express');
const _ = require('lodash');
const libxmljs = require('libxmljs');
const querystring = require('querystring');

const IP = '0.0.0.0';
const PORT = 8082;
const app = express();

app.use(express.static('static'));

const products = {
    1 : {
        NAME : 'T-Shirts',
        PRODUCT_ID : 1,
        INVENTORY : {
            XS : 10,
            S : 20,
            M : 30,
            L : 40,
            XL : 50,
            XXL : 60,
            XXXL : 70,
        },
    },
    2 : {
        NAME : 'Hoodies',
        PRODUCT_ID : 2,
        INVENTORY : {
            xs : 10,
            s : 20,
            m : 30,
            l : 40,
            xl : 50,
            xxl : 60,
            xxxl : 70,
        },
    },
    3 : {
        NAME : 'Beanies',
        PRODUCT_ID : 3,
        INVENTORY : {
            black : 100,
            white : 100,
        },
    },
};

const router = express.Router();

router.use(express.text({ type : '*/*' }));
router.use((req, res, next) => {
    req.headers.contentType = req.headers['content-type'];
    next();
});

router.post('/stockCheck', async (req, res) => {
    if (req.headers.contentType === 'application/x-www-form-urlencoded') {
        const size = req.body.size;

        const parsed = querystring.parse(req.body);
        const productId = parsed.productId;

        res.status(200).send({
            productId,
            value : products[productId],
        });
    } else if (req.headers.contentType === 'text/xml' || req.headers.contentType === 'application/xml' ) {
        const parsed = await libxmljs.parseXmlAsync(req.body, { replaceEntities : true });

        const productId = _.result(parsed.find('productId'), '0.text') || parsed.root().text();

        res.status(200).send({
            productId,
            value : products[productId],
        });
    } else {atus(400).send('Unsupported content type');
    }
        res.st
});

app.use('/', router);

app.listen(PORT, IP, () => {
    console.log(`Server is running on http://${IP}:${PORT}`);
});