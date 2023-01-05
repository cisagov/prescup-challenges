package edu.cmu.sei.cert.prescup21.ecommerce.repo;

import org.springframework.data.repository.CrudRepository;

import edu.cmu.sei.cert.prescup21.ecommerce.model.Product;

public interface ProductRepository extends CrudRepository<Product, Long>
{

}
