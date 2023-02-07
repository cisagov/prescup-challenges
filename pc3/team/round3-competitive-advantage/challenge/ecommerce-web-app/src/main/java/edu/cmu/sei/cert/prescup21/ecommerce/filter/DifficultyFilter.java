package edu.cmu.sei.cert.prescup21.ecommerce.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.GenericFilterBean;

import edu.cmu.sei.cert.prescup21.ecommerce.enumeration.State;
import edu.cmu.sei.cert.prescup21.ecommerce.util.GameState;

public class DifficultyFilter extends GenericFilterBean
{
	private GameState gameState = null;
	
	@Override
	public void doFilter( ServletRequest request, ServletResponse response, FilterChain chain ) throws IOException, ServletException
	{
	  if( gameState == null )
	  {
      ServletContext servletContext = request.getServletContext();
      WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
      gameState = webApplicationContext.getBean( GameState.class );
	  }
		
		if( gameState.currentState() == State.EASY )
		{
			System.out.println( "WE ARE IN EASY MODE STILL" );
		}
		else
		{
			// reject requests that dont have "Mozilla/5.0" in the user agent
			// reject requests that are POSTs that have no referer header set
			if( request instanceof HttpServletRequest && ((HttpServletRequest)request).getMethod().equalsIgnoreCase( "POST" ) )
			{
				String ua = ((HttpServletRequest)request).getHeader( "User-Agent" );
				String rf = ((HttpServletRequest)request).getHeader( "Referer" );
				
				if( rf == null || ua == null || rf.strip().length() == 0 || !ua.contains( "Mozilla/5.0" ) )
				{
					// bot detected. break the chain!
					return;
				}
			}
		}
		chain.doFilter( request, response );
	}

}
