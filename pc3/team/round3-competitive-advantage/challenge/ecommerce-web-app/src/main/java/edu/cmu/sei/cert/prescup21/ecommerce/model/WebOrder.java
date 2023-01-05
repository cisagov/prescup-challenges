package edu.cmu.sei.cert.prescup21.ecommerce.model;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.OrderStatus;

@Entity
public class WebOrder
{
	private Long id;
	private String user;
	private LocalDateTime created;
	private OrderStatus status;
	private BigDecimal total;
	private List<OrderLine> orderLines = new ArrayList<OrderLine>();

	public void addOredrLine( OrderLine ol )
	{
		orderLines.add( ol );
		ol.setWebOrder( this );
		update();
	}

	public void removeOrderLine( OrderLine ol )
	{
		orderLines.remove( ol );
		ol.setWebOrder( null );
		update();
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

	public String getUser()
	{
		return user;
	}

	public void setUser( String user )
	{
		this.user = user;
	}

	public LocalDateTime getCreated()
	{
		return created;
	}

	public void setCreated( LocalDateTime created )
	{
		this.created = created;
	}

	@Enumerated( EnumType.STRING )
	public OrderStatus getStatus()
	{
		return status;
	}

	public void setStatus( OrderStatus status )
	{
		this.status = status;
	}

	public BigDecimal getTotal()
	{
		return total;
	}

	public void setTotal( BigDecimal total )
	{
		this.total = total;
	}

	@OneToMany( mappedBy = "webOrder", cascade = CascadeType.ALL, orphanRemoval = true )
	public List<OrderLine> getOrderLines()
	{
		return orderLines;
	}

	public void setOrderLines( List<OrderLine> orderLines )
	{
		this.orderLines = orderLines;
	}

	public void update()
	{
		BigDecimal t = new BigDecimal( "0.00" );
		for( OrderLine ol : orderLines )
		{
			t = t.add( ol.getProduct().getPrice().multiply( new BigDecimal( ol.getQuantity() ) ) );
		}

		this.setTotal( t );
	}

}
