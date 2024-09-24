const { Product } = require('../model/Product');

exports.createProduct = async (req, res) => {
  // this product we have to get from API body
  const product = new Product(req.body);
  product.discountPrice=product.price*(100-product.discountPercentage)/100;
  try {
    const doc = await product.save();
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.updateAllProductsDiscountPrice= async function () {
  try {
    const products = await Product.find({});

    for (const product of products) {
      product.discountPrice = Math.round(product.price * (1 - product.discountPercentage / 100));
      await product.save();
    }

    console.log('Discount prices updated for all products.');
  } catch (err) {
    console.error('Error updating discount prices:', err);
  }
}

exports.fetchAllProducts = async (req, res) => {
  let condition={}
  if(!req.query.admin){
    condition.deleted={$ne:true}
  }
  let query = Product.find(condition);
  let totalProductsQuery = Product.find({deleted:{$ne:true}});
  if (req.query.category) {
    query = query.find({ category: {$in:req.query.category.split(',')} });
    totalProductsQuery = totalProductsQuery.find({
      category: {$in:req.query.category.split(',')},
    });
  }
  if (req.query.brand) {
    query = query.find({ brand: {$in:req.query.brand.split(',')} });
    totalProductsQuery = totalProductsQuery.find({ brand: {$in:req.query.brand.split(',') }});
  }
  //TODO : How to get sort on discounted Price not on Actual price
  if (req.query._sort && req.query._order) {
    query = query.sort({ [req.query._sort]: req.query._order });
  }

  const totalDocs = await totalProductsQuery.count().exec();

  if (req.query._page && req.query._limit) {
    const pageSize = req.query._limit;
    const page = req.query._page;
    query = query.skip(pageSize * (page - 1)).limit(pageSize);
  }

  try {
    const docs = await query.exec();
    res.set('X-Total-Count', totalDocs);
    res.status(200).json(docs);
  } catch (err) {
    res.status(400).json(err);
  }
};

exports.fetchProductById = async (req, res) => {
  const { id } = req.params;

  try {
    const product = await Product.findById(id);
    res.status(200).json(product);
  } catch (err) {
    res.status(400).json(err);
  }
};

const { User } = require('../model/User');

exports.updateProduct = async (req, res) => {
  const { id } = req.params;
  try {
    const product = await Product.findByIdAndUpdate(id, req.body, {new:true});
    product.discountPrice = Math.round(product.price*(1-product.discountPercentage/100))
    const updatedProduct = await product.save()
    res.status(200).json(updatedProduct);
  } catch (err) {
    res.status(400).json(err);
  }
};