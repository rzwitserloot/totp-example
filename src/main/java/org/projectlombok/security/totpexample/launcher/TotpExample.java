package org.projectlombok.security.totpexample.launcher;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.projectlombok.security.totpexample.Crypto;
import org.projectlombok.security.totpexample.SessionStore;
import org.projectlombok.security.totpexample.ResourcesHome;
import org.projectlombok.security.totpexample.Totp;
import org.projectlombok.security.totpexample.UserStore;
import org.projectlombok.security.totpexample.impl.DbBasedSessionStore;
import org.projectlombok.security.totpexample.impl.DbBasedUserStore;
import org.projectlombok.security.totpexample.servlets.ConfirmTotpLoginServlet;
import org.projectlombok.security.totpexample.servlets.ConfirmTotpSetupServlet;
import org.projectlombok.security.totpexample.servlets.HomepageServlet;
import org.projectlombok.security.totpexample.servlets.LoggedInUsersServlet;
import org.projectlombok.security.totpexample.servlets.LoginServlet;
import org.projectlombok.security.totpexample.servlets.LogoutServlet;
import org.projectlombok.security.totpexample.servlets.QrServlet;
import org.projectlombok.security.totpexample.servlets.SetupTotpServlet;
import org.projectlombok.security.totpexample.servlets.SignupServlet;
import org.projectlombok.security.totpexample.servlets.StaticFilesServlet;
import org.projectlombok.security.totpexample.servlets.TroubleshootTotpServlet;
import org.projectlombok.security.totpexample.servlets.VerifyTotpServlet;

import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;

/**
 * There is nothing particularly special about this code; it just launches jetty
 * pre-configured to port 8837 and with our servlets.
 * 
 * This file should not be in your project.
 * <p>
 * The servlets that this application serves up are:
 * 
 * /                   HomepageServlet         Home page of users that aren't logged in.</li>
 * 
 * /signup             SignupServlet           Begins the signup process
 * /setup-totp         SetupTotpServlet        Shows the TOTP setup QR code and instructions to complete the signup process.
 * /confirm-totp-setup ConfirmTotpSetupServlet Completes the signup process and redirects to /main
 * 
 * /login              LoginServlet            Begins the login process
 * /verify-totp        VerifyTotpServlet       Asks the user to verify their login by entering the TOTP code shown on their device.
 * /troubleshoot-totp  TroubleshootTotpServlet Asks the user to verify their login even after entering a wrong TOTP code by asking for 3 consecutive codes.
 * /confirm-totp-login ConfirmTotpLoginServlet Completes the login process and redirects to /main
 * 
 * /main               LoggedInUsersServlet    Home page of users that are logged in.
 * /logout             LogoutServlet           Logs a user out then redirects to /
 * 
 * (the rest)          StaticFilesServlet      Serves up static resources; the CSS and the font files. You don't need to look at this, your web application already has facilities to serve static resources.
 * 
 * Check those source files, in that order, to learn about how to implement TOTP in your own project.
 */
public class TotpExample {
	public static void main(String[] args) throws Exception {
		Server server = new Server(8837);
		ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");
		
		Crypto crypto = new Crypto();
		Configuration templates = createTemplateConfiguration();
		SessionStore sessions = createSessionStore(crypto);
		UserStore users = createUserStore(crypto);
		Totp totp = new Totp(users, sessions, crypto);
		
		context.addServlet(new ServletHolder(new HomepageServlet(templates, sessions)), ""); // The empty string is jetty code for '/'.
		context.addServlet(new ServletHolder(new LogoutServlet(users, sessions)), "/logout");
		context.addServlet(new ServletHolder(new LoggedInUsersServlet(templates, users, sessions)), "/main");
		
		context.addServlet(new ServletHolder(new SignupServlet(templates, sessions)), "/signup");
		context.addServlet(new ServletHolder(new SetupTotpServlet(templates, users, sessions, totp)), "/setup-totp");
		context.addServlet(new ServletHolder(new ConfirmTotpSetupServlet(users, sessions, totp)), "/confirm-totp-setup");
		
		context.addServlet(new ServletHolder(new LoginServlet(templates, sessions)), "/login");
		context.addServlet(new ServletHolder(new VerifyTotpServlet(templates, users, sessions, totp)), "/verify-totp");
		context.addServlet(new ServletHolder(new TroubleshootTotpServlet(templates, sessions, totp)), "/troubleshoot-totp");
		context.addServlet(new ServletHolder(new ConfirmTotpLoginServlet(users, sessions, totp)), "/confirm-totp-login");
		
		context.addServlet(new ServletHolder(new QrServlet(sessions)), "/qrcode");
		
		context.addServlet(new ServletHolder(new StaticFilesServlet()), "/"); // '/' is jetty code for 'everything else'.
		
		server.setHandler(context);
		
		server.start();
		server.join();
	}
	
	private static SessionStore createSessionStore(Crypto crypto) {
		// This is a demo implementation of a session store, built around an embedded DB engine that works with local files.
		return new DbBasedSessionStore(crypto);
	}
	
	private static UserStore createUserStore(Crypto crypto) {
		// This is a demo implementation of a session store, built around an embedded DB engine that works with local files.
		return new DbBasedUserStore(crypto);
	}
	
	private static Configuration createTemplateConfiguration() {
		// The templates rendered by this demo application are based on Apache Freemarker.
		
		Configuration cfg = new Configuration(Configuration.VERSION_2_3_23);
		cfg.setClassLoaderForTemplateLoading(TotpExample.class.getClassLoader(), ResourcesHome.class.getPackage().getName().replace(".", "/"));
		cfg.setDefaultEncoding("UTF-8");
		
		// SECURITY NOTE: You should use the TemplateExceptionHandler.RETHROW_HANDLER in production!
		cfg.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
		return cfg;
	}
}
