package edu.cmu.sei.cert.prescup21.ecommerce.controller;

import java.math.BigDecimal;

import javax.annotation.security.PermitAll;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import edu.cmu.sei.cert.prescup21.ecommerce.form.FinalSubmit;
import edu.cmu.sei.cert.prescup21.ecommerce.model.Product;
import edu.cmu.sei.cert.prescup21.ecommerce.model.WebOrder;
import edu.cmu.sei.cert.prescup21.ecommerce.repo.ProductRepository;
import edu.cmu.sei.cert.prescup21.ecommerce.service.CartService;
import edu.cmu.sei.cert.prescup21.ecommerce.util.UserTools;

@Controller
public class Web
{
	private ProductRepository productRepo;
	private CartService cartService;

	public Web( ProductRepository productRepo, CartService cartService )
	{
		this.productRepo = productRepo;
		this.cartService = cartService;
	}

	// open
	@PermitAll
	@GetMapping( "/" )
	public String index( Model model, CsrfToken csrf )
	{
		model.addAttribute( "title", "PresCup Index Page" );
		model.addAttribute( "module", "home" );
		model.addAttribute( "username", UserTools.loggedInUserName() );
		return "myIndex";
	}

	// protected
	@GetMapping( "/about" )
	public String welcome( Model model )
	{
		model.addAttribute( "module", "about" );
		model.addAttribute( "username", UserTools.loggedInUserName() );
		return "about";
	}

	// protected
	@GetMapping( "/products" )
	public String products( Model model )
	{
		Iterable<Product> products = productRepo.findAll();

		model.addAttribute( "module", "products" );
		model.addAttribute( "title", "Products" );
		model.addAttribute( "products", products );
		model.addAttribute( "username", UserTools.loggedInUserName() );
		return "products";
	}

	@GetMapping( "/product/{productId}" )
	public String productDetail( Model model, @PathVariable String productId )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "products" );
		model.addAttribute( "productId", productId );
		model.addAttribute( "product", productRepo.findById( Long.parseLong( productId ) ).get() );
		return "productDetail";
	}

	// protected
	@GetMapping( "/cart" )
	public String cart( Model model )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "cart" );
		model.addAttribute( "titel", "Cart" );
		model.addAttribute( "cart", cartService.fetchCart() );
		return "cart";
	}

	// protected
	@GetMapping( "/checkout" )
	public String checkout( Model model )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "checkout" );
		model.addAttribute( "title", "Checkout" );
		model.addAttribute( "cart", cartService.fetchCart() );
		return "checkout";
	}
	
	@PostMapping( "/checkout" )
	public String checkoutSubmit( Model model, @ModelAttribute FinalSubmit form )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "checkout" );
		model.addAttribute( "title", "Checkout - Submit" );
		model.addAttribute( "cart", cartService.fetchCart() );
		
		WebOrder finished = cartService.checkout( form );
		
		if( finished == null )
		{
			return "checkout";
		}
		
		
		return "redirect:/revieworder";
	}
	
	@GetMapping( "/revieworder" )
	public String revieworder( Model model )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "revieworder" );
		model.addAttribute( "titel", "Review Order" );
		WebOrder lastOrder = cartService.lastOrder();
		
		if( lastOrder == null )
			return "redirect:/cart";
		
		model.addAttribute( "order", lastOrder );
		return "review";
	}

	@GetMapping( "/orderconfirmation" )
	public String orderconfirmation( Model model )
	{
		model.addAttribute( "username", UserTools.loggedInUserName() );
		model.addAttribute( "module", "orderconfirmation" );
		return "orderconfirmation";
	}
}
