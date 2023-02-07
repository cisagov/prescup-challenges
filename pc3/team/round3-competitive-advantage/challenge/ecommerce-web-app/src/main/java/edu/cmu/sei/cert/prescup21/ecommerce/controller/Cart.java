package edu.cmu.sei.cert.prescup21.ecommerce.controller;

import java.math.BigDecimal;
import java.util.Iterator;
import java.util.Optional;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;

import edu.cmu.sei.cert.prescup21.ecommerce.model.OrderLine;
import edu.cmu.sei.cert.prescup21.ecommerce.model.Product;
import edu.cmu.sei.cert.prescup21.ecommerce.model.WebOrder;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.ProductRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.WebOrderRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.responses.CartAddResponse;
import edu.cmu.sei.cert.prescup21.ecommerce.service.CartService;

@RestController
@RequestMapping( "/rest" )
public class Cart
{
	private CartService cartService;
	private ProductRepository productRepo;
	private WebOrderRepository webOrderRepo;

	public Cart( CartService cartService, ProductRepository productRepo, WebOrderRepository webOrderRepo )
	{
		this.cartService = cartService;
		this.productRepo = productRepo;
		this.webOrderRepo = webOrderRepo;
	}

	// @RequestMapping(value = "/test", method = RequestMethod.POST, consumes =
	// MediaType.APPLICATION_JSON_UTF8_VALUE )
	@PostMapping( "/test" )
	public String publishData( @RequestBody JsonNode requestBody, CsrfToken csrf )
	{
		if( csrf != null && requestBody.get( "csrfToken" ) != null && csrf.getToken().equals( requestBody.get( "csrfToken" ).textValue() ) )
		{
			return requestBody.get( "alabaster" ).textValue() + " " + csrf.getToken();
		}

		return "invalid request";

	}

	@PostMapping( "/cart" )
	public CartAddResponse addItemsToCart( @RequestBody JsonNode requestBody, CsrfToken csrf )
	{
		CartAddResponse car = new CartAddResponse();
		WebOrder cart = cartService.fetchCart();

		// CSRF test just to make the scripts work harder.
		if( csrf != null &&
				requestBody.get( "csrfToken" ) != null &&
				csrf.getToken().equals( requestBody.get( "csrfToken" ).textValue() ) &&
				requestBody.get( "FSTAT" ).textValue().equals( "039" ) )// no clue what FSTAT is but its going in here
		{
			car.setMessage( "okay so far" );
			int idx = 1;
			String price, name, q, idL;
			int quantity;
			long id;
			Iterator<String> iter = requestBody.fieldNames();
			while( iter.hasNext() )
			{
				System.out.println( iter.next() );
			}
			while( requestBody.get( String.format( "ID-%05d", idx ) ) != null )
			{
				idL = requestBody.get( String.format( "ID-%05d", idx ) ).asText();
				price = requestBody.get( String.format( "PRICE-%05d", idx ) ).textValue();
				name = requestBody.get( String.format( "NAME-%05d", idx ) ).textValue();
				q = requestBody.get( String.format( "QUANTITY-%05d", idx ) ).asText();
				
				// done with idx, increment it
				idx++;
				
				if( price == null || name == null )
				{
					car.setMessage( "Invalid requst." + price + " " + name );
					return car;
				}

				try
				{
					BigDecimal bdPrice = new BigDecimal( price );
					id = Long.parseLong( idL );
					Optional<Product> p = productRepo.findById( id );
					if( q.strip().length() == 0 )
						continue;
					quantity = Integer.parseInt( q );
					if( !p.isPresent() )
					{
						car.setMessage( "invalide request" );
						return car;
					}
					Product pp = p.get();
					if( !pp.getName().equals( name ) || !pp.getPrice().equals( bdPrice ) || quantity < 0 )
					{
						car.setMessage( "invalid request" );
						return car;
					}
					// okay at this point this part of the request is valid, so add the
					// item to the cart

					OrderLine ol = null;
					for( OrderLine olt : cart.getOrderLines() )
					{
						if( olt.getProduct().getId().equals( id ) )
							ol = olt;
					}
					
					quantity = Math.min( quantity, pp.getQuantity() );
					
					if( ol == null )
					{
						ol = new OrderLine();
						ol.setProduct( pp );
						ol.setQuantity( quantity );
						cart.addOredrLine( ol );
					}
					
					ol.setQuantity( quantity );

					car.setMessage( car.getMessage() + " added " + name + " " + quantity );
				}
				catch( NumberFormatException e )
				{
					car.setMessage( "Invalid request...nfe" );
					return car;
				}
				
			}
		}
		else
		{
			car.setMessage( "Invalid request." );
			return car;
		}

		webOrderRepo.save( cart );
		return car;
	}

	@GetMapping( "/cart" )
	public WebOrder loadCart()
	{
		return cartService.fetchCart();
	}
}
