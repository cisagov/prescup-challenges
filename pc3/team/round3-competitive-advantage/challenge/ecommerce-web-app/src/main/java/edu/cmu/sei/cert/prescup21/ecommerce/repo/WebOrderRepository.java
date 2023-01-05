package edu.cmu.sei.cert.prescup21.ecommerce.repo;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.OrderStatus;
import edu.cmu.sei.cert.prescup21.ecommerce.model.WebOrder;

public interface WebOrderRepository extends CrudRepository<WebOrder, Long>
{
	Optional<WebOrder> findByUserAndStatus( String user, OrderStatus status );
	Optional<WebOrder> findFirstByUserAndStatusOrderByIdDesc( String user, OrderStatus status );
	List<WebOrder> findAllByUserAndStatus( String user, OrderStatus submitted );
}
