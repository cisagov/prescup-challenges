package edu.cmu.sei.cert.prescup21.ecommerce.model;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
public class OrderLine
{
	private Long id;
	private WebOrder webOrder;
	private Product product;
	private Integer quantity;

	@ManyToOne( fetch = FetchType.LAZY )
	@JsonIgnore
	public WebOrder getWebOrder()
	{
		return webOrder;
	}

	public void setWebOrder( WebOrder order )
	{
		this.webOrder = order;
	}

	public Integer getQuantity()
	{
		return quantity;
	}

	public void setQuantity( Integer quantity )
	{
		this.quantity = quantity;
	}

	@ManyToOne( cascade = { CascadeType.PERSIST, CascadeType.MERGE } )
	public Product getProduct()
	{
		return product;
	}

	public void setProduct( Product product )
	{
		this.product = product;
	}

	@Id
	@GeneratedValue( strategy = GenerationType.IDENTITY )
	public Long getId()
	{
		return id;
	}

	public void setId( Long id )
	{
		this.id = id;
	}

}
