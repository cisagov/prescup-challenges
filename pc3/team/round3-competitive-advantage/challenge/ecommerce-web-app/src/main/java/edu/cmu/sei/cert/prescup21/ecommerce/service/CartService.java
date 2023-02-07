package edu.cmu.sei.cert.prescup21.ecommerce.service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.OrderStatus;
import edu.cmu.sei.cert.prescup21.ecommerce.form.FinalSubmit;
import edu.cmu.sei.cert.prescup21.ecommerce.model.OrderLine;
import edu.cmu.sei.cert.prescup21.ecommerce.model.WebOrder;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.WebOrderRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.util.UserTools;

@Service
public class CartService
{
	private WebOrderRepository webOrderRepo;

	public CartService( WebOrderRepository webOrderRepo )
	{
		this.webOrderRepo = webOrderRepo;
	}

	public WebOrder fetchCart()
	{
		String user = UserTools.loggedInUserName();
		Optional<WebOrder> wo = webOrderRepo.findByUserAndStatus( user, OrderStatus.CART );

		if( wo.isPresent() )
			return updateCart( wo.get() );

		return initCart();
	}
	
	public WebOrder lastOrder()
	{
		String user = UserTools.loggedInUserName();
		Optional<WebOrder> wo = webOrderRepo.findFirstByUserAndStatusOrderByIdDesc( user, OrderStatus.SUBMITTED );
		if( wo.isPresent() )
			return wo.get();
		
		return null;
	}

	private WebOrder updateCart( WebOrder cart )
	{
		for( OrderLine ol : cart.getOrderLines() )
		{
			// set the purchase quantity to either whats requested or whats available, whichever is smaller
			ol.setQuantity( Math.min( ol.getQuantity(), ol.getProduct().getQuantity() ) );
		}
		return webOrderRepo.save( cart );
	}
	
	private WebOrder initCart()
	{
		WebOrder wo = new WebOrder();

		wo.setCreated( LocalDateTime.now() );
		wo.setStatus( OrderStatus.CART );
		wo.setTotal( new BigDecimal( "0.00" ) );
		wo.setUser( UserTools.loggedInUserName() );

		return webOrderRepo.save( wo );
	}

	public synchronized WebOrder checkout( FinalSubmit form )
	{
		
		if( form.getPayment() == null ||
				!form.getFSTAT().equals( "039" ) )
			return null;
		
		WebOrder cart = fetchCart();
		
		int qty = 0;
		
		List<OrderLine> toRemove = new ArrayList<OrderLine>();
		
		for( OrderLine ol : cart.getOrderLines() )
		{
			// set the purchase quantity to either whats requested or whats available, whichever is smaller
			ol.setQuantity( Math.min( ol.getQuantity(), ol.getProduct().getQuantity() ) );
			qty += ol.getQuantity();
			if( ol.getQuantity() == 0 )
				toRemove.add( ol );
			// remove product from inventory
			ol.getProduct().setQuantity( ol.getProduct().getQuantity() - ol.getQuantity() );
		}
		
		if( qty == 0 )
		{
			for( OrderLine ol : toRemove )
				cart.removeOrderLine( ol );
		}
		else
		{
			cart.setStatus( OrderStatus.SUBMITTED );
		}
		
		cart.update();
		
		webOrderRepo.save( cart );
		return cart;
	}

	public void undoOrder()
	{
		WebOrder cart = lastOrder();
		
		// sanity check
		if( ( cart.getTotal().compareTo( BigDecimal.ZERO ) == 0 ) && cart.getStatus() == OrderStatus.SUBMITTED )
		{
			for( OrderLine ol : cart.getOrderLines() )
			{
				cart.removeOrderLine( ol );
			}
			
			cart.setStatus( OrderStatus.CART );
			webOrderRepo.save( cart );
		}
	}
}
