const express = require('express');
const { createProduct, fetchAllProducts, fetchProductById, updateProduct, updateAllProductsDiscountPrice } = require('../controller/Product');

const router = express.Router();

router.post('/', createProduct)
      .get('/', fetchAllProducts)
      .get('/:id', fetchProductById)
      .patch('/:id', updateProduct)
      .patch('/updateDiscountPrice', updateAllProductsDiscountPrice); // New endpoint for updating all products' discount prices

exports.router = router;
