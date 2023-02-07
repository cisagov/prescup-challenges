package edu.cmu.sei.cert.prescup21.ecommerce.util;

import java.util.Enumeration;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class UserTools
{
	public static String loggedInUserName()
	{
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if( authentication.getPrincipal() instanceof UserDetails )
		{
			return ( (UserDetails) authentication.getPrincipal() ).getUsername();
		}
		return "unknown";
	}

	public static CsrfToken getCurrentCsrfToken()
	{
		// quick-test
		ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
		HttpSession session = attr.getRequest().getSession( false );
		if( session == null )
		{
			return null;
		}
		Enumeration<String> e = session.getAttributeNames();
		while( e.hasMoreElements() )
		{
			String s = e.nextElement();
		}
		return (CsrfToken) session.getAttribute( CsrfToken.class.getName() );
	}
}
