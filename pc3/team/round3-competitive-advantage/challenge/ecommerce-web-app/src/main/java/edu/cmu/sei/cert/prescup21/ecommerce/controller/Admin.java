package edu.cmu.sei.cert.prescup21.ecommerce.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.OrderStatus;
import edu.cmu.sei.cert.prescup21.ecommerce.form.StockForm;
import edu.cmu.sei.cert.prescup21.ecommerce.model.Product;
import edu.cmu.sei.cert.prescup21.ecommerce.model.WebOrder;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.ProductRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.WebOrderRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.util.GameState;

@RestController
@RequestMapping( "/admin/rest" )
public class Admin
{
	private ProductRepository productRepo;
	private WebOrderRepository webOrderRepo;
	private GameState gameState;
	
	public Admin( ProductRepository productRepo, WebOrderRepository webOrderRepo, GameState gs )
	{
		this.productRepo = productRepo;
		this.webOrderRepo = webOrderRepo;
		this.gameState = gs;
	}
	
	@GetMapping("/orders/{user}")
	public List<WebOrder> fetchOrders( @PathVariable String user )
	{
		List<WebOrder> orders = webOrderRepo.findAllByUserAndStatus( user, OrderStatus.SUBMITTED );
		
		return orders;
	}
	
	@PostMapping("/difficulty/{mode}")
	public String setDifficulty( @PathVariable String mode )
	{
		
		if( "EASY".equals( mode ) )
			gameState.easyState();
		else if( "HARD".equals( mode ) )
			gameState.hardState();
		
		return gameState.currentState().toString();
	}
	
	@PostMapping( "/addStock/{product}" )
	public Product addStock( @PathVariable Product product, @RequestBody StockForm form )
	{
		product.setQuantity( form.getQuantity() );
		return productRepo.save( product );
	}
	
	@PostMapping( "/define" )
	public Product defineProduct( @RequestBody Product p )
	{
		Product w = new Product();
		w.setName( p.getName() );
		w.setPrice( p.getPrice() );
		w.setCost(p.getCost());
		w.setDescription(p.getDescription());
		w.setQuantity( 0 );
		
		return productRepo.save(w);
	}
}
