package edu.cmu.sei.cert.prescup21.ecommerce.model;

import java.math.BigDecimal;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
public class Product
{
	private Long id;
	private String name;
	private String description;
	private BigDecimal price;
	private BigDecimal cost;
	private Integer quantity;

	public String getDescription()
	{
		return description;
	}

	public void setDescription( String description )
	{
		this.description = description;
	}

	public BigDecimal getCost()
	{
		return cost;
	}

	public void setCost( BigDecimal cost )
	{
		this.cost = cost;
	}

	public Integer getQuantity()
	{
		return quantity;
	}

	public void setQuantity( Integer quantity )
	{
		this.quantity = quantity;
	}

	public String getName()
	{
		return name;
	}

	public void setName( String name )
	{
		this.name = name;
	}

	public BigDecimal getPrice()
	{
		return price;
	}

	public void setPrice( BigDecimal price )
	{
		this.price = price;
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
