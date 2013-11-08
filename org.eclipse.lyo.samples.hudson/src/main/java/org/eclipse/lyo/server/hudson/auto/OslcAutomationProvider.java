/*******************************************************************************
 * Copyright (c) 2013 IBM Corporation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *  
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *
 *     Samuel Padgett - initial implementation
 *******************************************************************************/
package org.eclipse.lyo.server.hudson.auto;

import hudson.Extension;
import hudson.model.ParameterValue;
import hudson.model.Result;
import hudson.model.RootAction;
import hudson.model.SimpleParameterDefinition;
import hudson.model.AbstractProject;
import hudson.model.BooleanParameterDefinition;
import hudson.model.BooleanParameterValue;
import hudson.model.Cause;
import hudson.model.ChoiceParameterDefinition;
import hudson.model.Hudson;
import hudson.model.Job;
import hudson.model.ParameterDefinition;
import hudson.model.ParametersAction;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.PasswordParameterDefinition;
import hudson.model.Run;
import hudson.model.StringParameterDefinition;
import hudson.model.StringParameterValue;
import hudson.security.csrf.CrumbIssuer;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import org.eclipse.lyo.core.query.ComparisonTerm;
import org.eclipse.lyo.core.query.InTerm;
import org.eclipse.lyo.core.query.PName;
import org.eclipse.lyo.core.query.ParseException;
import org.eclipse.lyo.core.query.QueryUtils;
import org.eclipse.lyo.core.query.SimpleTerm;
import org.eclipse.lyo.core.query.UriRefValue;
import org.eclipse.lyo.core.query.Value;
import org.eclipse.lyo.core.query.WhereClause;
import org.eclipse.lyo.core.utils.marshallers.MarshallerConstants;
import org.eclipse.lyo.core.utils.marshallers.OSLC4JContext;
import org.eclipse.lyo.core.utils.marshallers.OSLC4JMarshaller;
import org.eclipse.lyo.core.utils.marshallers.OSLC4JUnmarshaller;
import org.eclipse.lyo.oslc4j.automation.AutomationConstants;
import org.eclipse.lyo.oslc4j.automation.AutomationPlan;
import org.eclipse.lyo.oslc4j.automation.AutomationRequest;
import org.eclipse.lyo.oslc4j.automation.AutomationResult;
import org.eclipse.lyo.oslc4j.automation.ParameterInstance;
import org.eclipse.lyo.oslc4j.core.model.Compact;
import org.eclipse.lyo.oslc4j.core.model.CreationFactory;
import org.eclipse.lyo.oslc4j.core.model.Dialog;
import org.eclipse.lyo.oslc4j.core.model.Link;
import org.eclipse.lyo.oslc4j.core.model.Occurs;
import org.eclipse.lyo.oslc4j.core.model.OslcConstants;
import org.eclipse.lyo.oslc4j.core.model.OslcMediaType;
import org.eclipse.lyo.oslc4j.core.model.PrefixDefinition;
import org.eclipse.lyo.oslc4j.core.model.Preview;
import org.eclipse.lyo.oslc4j.core.model.Property;
import org.eclipse.lyo.oslc4j.core.model.Publisher;
import org.eclipse.lyo.oslc4j.core.model.QueryCapability;
import org.eclipse.lyo.oslc4j.core.model.Service;
import org.eclipse.lyo.oslc4j.core.model.ServiceProvider;
import org.eclipse.lyo.oslc4j.utils.AcceptUtil;
import org.eclipse.lyo.server.hudson.auto.resource.HudsonAutoConstants;
import org.eclipse.lyo.server.hudson.auto.resource.QueryResponse;
import org.eclipse.lyo.server.hudson.auto.resource.ResponseInfo;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.framework.io.WriterOutputStream;

import com.hp.hpl.jena.datatypes.xsd.XSDDatatype;

/**
 * Hudson and Jenkins OSLC Automation Provider.
 * 
 * @author Samuel Padgett <spadgett@us.ibm.com>
 */
@Extension
public class OslcAutomationProvider implements RootAction {

	/*
	 * Apache Wink doesn't work with a Hudson or Jenkins environment without
	 * this property. This static block must come before we instantiate a
	 * MediaType (or do anything with Wink).
	 */
	static {
		System.setProperty("javax.ws.rs.ext.RuntimeDelegate",
		        "org.apache.wink.common.internal.runtime.RuntimeDelegateImpl");
	}

	/**
	 * Acceptable media types for our automation provider. This array may only
	 * contain types supported by {@link OSLC4JMarshaller}.
	 */
	public static final MediaType[] ACCEPTABLE = {
		MediaType.TEXT_HTML_TYPE,
		OslcMediaType.APPLICATION_RDF_XML_TYPE,
		OslcMediaType.TEXT_TURTLE_TYPE,
		OslcMediaType.APPLICATION_XML_TYPE,
		OslcMediaType.APPLICATION_JSON_TYPE,
		OslcMediaType.APPLICATION_X_OSLC_COMPACT_XML_TYPE
	};
	
	/**
	 * All prefixes and namespaces used by this provider.
	 */
	private static final Map<String, String> PREFIX_MAP;
	static {
		Map<String, String> prefixes = new HashMap<String, String>();
		prefixes.put(OslcConstants.DCTERMS_NAMESPACE_PREFIX, OslcConstants.DCTERMS_NAMESPACE);
		prefixes.put(OslcConstants.OSLC_CORE_NAMESPACE_PREFIX, OslcConstants.OSLC_CORE_NAMESPACE);
		prefixes.put(OslcConstants.RDF_NAMESPACE_PREFIX, OslcConstants.RDF_NAMESPACE);
		prefixes.put(OslcConstants.RDFS_NAMESPACE_PREFIX, OslcConstants.RDFS_NAMESPACE);
		prefixes.put(AutomationConstants.FOAF_NAMESPACE_PREFIX, AutomationConstants.FOAF_NAMESPACE);
		prefixes.put(AutomationConstants.AUTOMATION_PREFIX, AutomationConstants.AUTOMATION_NAMESPACE);
		prefixes.put(HudsonAutoConstants.PREFIX, HudsonAutoConstants.NAMESPACE);
		
		PREFIX_MAP = Collections.unmodifiableMap(prefixes);
	}

	private static final Logger LOG = Logger.getLogger(OslcAutomationProvider.class.getName());

	// You will need to rename the doXXX() methods below if you change these constants.
	// Also update any delegated dialog JavaScript, which can't use these constants.
	private static final String PATH_AUTO = "auto";
	private static final String PATH_JOB = "job";
	private static final String PATH_RUN = "run";
	private static final String PATH_REQUEST = "request";
	private static final String PATH_PREVIEW = "preview";

    @Override
	public String getDisplayName() {
		return "OSLC Automation Provider";
	}

    @Override
	public String getIconFileName() {
		return "/plugin/hudson-oslc-auto/images/oslc.png";
	}

    @Override
	public String getUrlName() {
		return PATH_AUTO;
	}
    
    public String doHello() {
    	return "Hello from the OSLC Automation plugin!";
    }

	public void doProvider(StaplerRequest request, StaplerResponse response)
	        throws URISyntaxException, WebApplicationException, IOException {
		requireGET(request);

		ServiceProvider provider = new ServiceProvider();
		provider.setAbout(getProviderURI(request));
		provider.setTitle("OSLC Automation Provider for Hudson and Jenkins");
		provider.setPublisher(new Publisher("Eclipse Lyo", "urn:oslc:ServiceProvider"));

		final PrefixDefinition[] prefixDefinitions = getPrefixDefinitions();
		provider.setPrefixDefinitions(prefixDefinitions);

		Service service = new Service();
		provider.addService(service);
		service.setDomain(new URI(AutomationConstants.AUTOMATION_DOMAIN));
		service.setUsages(new URI[] { new URI(AutomationConstants.AUTOMATION_NAMESPACE + "Build") });

		QueryCapability queryJobs = new QueryCapability("Jobs",
		        getBaseUriBuilder(request).path("queryJobs").build());
		queryJobs.addResourceType(new URI(AutomationConstants.TYPE_AUTOMATION_PLAN));
		service.addQueryCapability(queryJobs);

		QueryCapability queryRuns = new QueryCapability("Runs",
		        getBaseUriBuilder(request).path("queryRuns").build());
		queryRuns.addResourceType(new URI(AutomationConstants.TYPE_AUTOMATION_RESULT));
		service.addQueryCapability(queryRuns);
		
		// Hudson uses crumbs to prevent CSRF attacks on POST requests. OSLC
		// interfaces cannot support this, however.
		// To workaround -- for now at least -- bake the crumb into the URL (mixing metaphors?).
		// Then we can use OAuth or another authentication mechanism to avoid CSRF problems.

		// FIXME: Is there a better way?
		CrumbIssuer issuer = Hudson.getInstance().getCrumbIssuer();
		String crumbName = issuer.getDescriptor().getCrumbRequestField();
		String crumb = issuer.getCrumb(null);
 
		CreationFactory scheduleBuild = new CreationFactory("Schedule Build",
		        getBaseUriBuilder(request).path("scheduleBuild").queryParam(crumbName, crumb).build());
		scheduleBuild.addResourceType(new URI(AutomationConstants.TYPE_AUTOMATION_REQUEST));
		service.addCreationFactory(scheduleBuild);
		
		Dialog selectJobs = new Dialog("Select Job", getBaseUriBuilder(request).path("selectJob").build());
		selectJobs.addResourceType(new URI(AutomationConstants.TYPE_AUTOMATION_PLAN));
		selectJobs.setHintHeight("400px");
		selectJobs.setHintWidth("600px");
		service.addSelectionDialog(selectJobs);

		marshal(request, response, provider);
	}

	private PrefixDefinition[] getPrefixDefinitions() throws URISyntaxException {
		final PrefixDefinition[] prefixDefinitions = new PrefixDefinition[PREFIX_MAP.size()];
		int i = 0;
		for (Map.Entry<String, String> entry : PREFIX_MAP.entrySet()) {
			prefixDefinitions[i++] = new PrefixDefinition(entry.getKey(), new URI(entry.getValue()));
		}

	    return prefixDefinitions;
    }

	/*
	 * Jobs query capability
	 */
	public void doQueryJobs(StaplerRequest request, StaplerResponse response)
	        throws IOException, URISyntaxException {
		requireGET(request);

        @SuppressWarnings("rawtypes")
        Collection<Job> jobs = Hudson.getInstance().getItems(Job.class);
		ArrayList<AutomationPlan> plans = new ArrayList<AutomationPlan>();
		for (Job<?, ?> job : jobs) {
			plans.add(toAutomationPlan(request, job));
		}

		marshalQueryResult(request, response, plans);
	}

	/*
	 * Jobs selection dialog
	 */
	public void doSelectJob(StaplerRequest request, StaplerResponse response)
	        throws ServletException, IOException {
		requireGET(request);
		response.forward(new JobSelectionDialog(), "dialog", request);
	}

	private Job<?, ?> getJob(String name) {
		return (Job<?, ?>) Hudson.getInstance().getItem(name);
	}

	// FIXME: Need to break up this method and clean up URL handling.
	public void doJob(StaplerRequest request, StaplerResponse response)
	        throws IOException, URISyntaxException, ServletException {
		requireGET(request);

		MediaType type = AcceptUtil.matchMediaType(request, ACCEPTABLE);
		if (type == null) {
			throw HttpResponses.status(HttpServletResponse.SC_NOT_ACCEPTABLE);
		}

		String restOfPath = request.getRestOfPath();
		if (restOfPath == null) {
			throw HttpResponses.notFound();
		}

		// Remove leading '/'
		restOfPath = restOfPath.substring(1);
		String segments[] = restOfPath.split("/");
		
		// URI patterns:
		//   <job-name>
		//   <job-name>/preview
		//   <job-name>/run/<run-number>
		//   <job-name>/run/<run-number>/preview
		//   <job-name>/run/<run-number>/request

		// Find the job.
		String jobName = segments[0];
		Job<?, ?> job = getJob(jobName);
		if (job == null) {
			throw HttpResponses.notFound();
		}

		// Is it a run?
		//   <job-name>/run/<run-number>
		if (segments.length >= 3 && PATH_RUN.equals(segments[1])) {
			String runNumber = segments[2];
			int i;
			try {
				i = Integer.valueOf(Integer.parseInt(runNumber));
			} catch (NumberFormatException e) {
				throw HttpResponses.notFound();
			}

			Run<?, ?> run = job.getBuildByNumber(i);
			if (run == null) {
				throw HttpResponses.notFound();
			}

			if (segments.length == 4) {
				// Is it a run preview?
				//   <job-name>/run/<run-number>/preview
				if (PATH_PREVIEW.equals(segments[3])) {
					/*
					 * See /hudson-oslc-auto/src/main/resources/hudson/model/Run/preview.jelly
					 */
					response.forward(run, "preview", request);
					return;
				}

				// Is it an AutomationRequest?
				//   <job-name>/run/<run-number>/request
				if (PATH_REQUEST.equals(segments[3])) {
					AutomationRequest autoRequest = toAutomationRequest(request, job, run);
					marshal(request, response, autoRequest);
				}
				
				if ("buildStatus".equals(segments[3])) {
					throw HttpResponses.redirectViaContextPath(run.getUrl() + "/buildStatus");
				}
			} else if (segments.length == 3) {	// <job-name>/run/<run-number>
				if (MediaType.TEXT_HTML_TYPE.isCompatible(type)) {
					throw HttpResponses.redirectViaContextPath(run.getUrl());
				}

				if (MarshallerConstants.MT_OSLC_COMPACT.isCompatible(type)) {
					handleCompact(request, response, job, run);
				} else {
					AutomationResult result = toAutomationResult(request, job, run);
					marshal(request, response, result);
				}
			} else {
				throw HttpResponses.notFound();
			}
		} else {
			// Is it a job preview?
			//   <job-name>/preview
			if (segments.length == 2 && PATH_PREVIEW.equals(segments[1])) {
				/*
				 * See /hudson-oslc-auto/src/main/resources/hudson/model/Job/preview.jelly
				 */
				response.forward(job, "preview", request);
				return;
			}

			if (segments.length != 1) {
				throw HttpResponses.notFound();
			}

			// Is it just a job name with no other segments?
			//   <job-name>
			if (MediaType.TEXT_HTML_TYPE.isCompatible(type)) {
				throw HttpResponses.redirectViaContextPath(job.getUrl());
			}
	
			if (MarshallerConstants.MT_OSLC_COMPACT.isCompatible(type)) {
				handleCompact(request, response, job);
			} else {
				AutomationPlan plan = toAutomationPlan(request, job);
				marshal(request, response, plan);
			}
		}
	}
	
	private void handleCompact(StaplerRequest request, StaplerResponse response, Job<?, ?> job) throws IOException,
	        URISyntaxException {
	   Compact c = new Compact(); 

	   c.setAbout(getJobURI(request, job));
	   c.setTitle(job.getFullDisplayName());
	   
	   String icon = request.getRootPath() + job.getBuildHealth().getIconUrl("16x16");
	   c.setIcon(new URI(icon));
	   
	   Preview p = new Preview();
	   p.setHintHeight("200px");
	   p.setHintWidth("400px");
	   p.setDocument(getJobPreviewURI(request, job));
	   c.setSmallPreview(p);

	   marshal(request, response, c);
    }

	private void handleCompact(StaplerRequest request,
	        StaplerResponse response, Job<?, ?> job, Run<?, ?> run) throws IOException,
	        URISyntaxException {
	   Compact c = new Compact(); 

	   c.setAbout(getRunURI(request, job, run));
	   c.setTitle(run.getFullDisplayName());
	   c.setShortTitle(run.getDisplayName());
	   
	   String relative = run.getIconColor().getImageOf("16x16");
	   // Remove context or it shows up twice since getRootPath() and getImageOf() both include it.
	   String icon = request.getRootPath() + relative.substring(request.getContextPath().length());
	   c.setIcon(new URI(icon));
	
	   Preview p = new Preview();
	   p.setHintHeight("300px");
	   p.setHintWidth("400px");
	   p.setDocument(getRunPreviewURI(request, job, run));
	   c.setSmallPreview(p);

	   marshal(request, response, c);
    }

	public void doScheduleBuild(StaplerRequest request, StaplerResponse response)
	        throws Exception {
		requirePOST(request);

		OSLC4JUnmarshaller unmarshaller = OSLC4JContext.newInstance().createUnmarshaller();

		String contentType = request.getContentType();
		if (contentType == null) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}
		unmarshaller.setMediaType(MediaType.valueOf(contentType));

		final AutomationRequest autoRequest =
				unmarshaller.unmarshal(request.getInputStream(), AutomationRequest.class);
		if (autoRequest == null) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		Link planLink = autoRequest.getExecutesAutomationPlan();
		if (planLink == null) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		URI planURI = planLink.getValue();
		String jobName = getJobNameFromURI(request, planURI);
		if (jobName == null) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		Job<?, ?> job = getJob(jobName);
		if (job == null) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		if (!job.isBuildable()) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		if (!(job instanceof AbstractProject)) {
			LOG.log(Level.WARNING, "Cannot schedule builds for jobs that don't extend AbstractProject: " + jobName);
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}

		AbstractProject<?, ?> project = (AbstractProject<?, ?>) job;
		int nextBuildNumber = project.getNextBuildNumber();
		Cause cause = new Cause() {
			@Override
			public String getShortDescription() {
				String description = autoRequest.getDescription();
				return description != null ? description : "OSLC Automation Request";
			}
		};
		
		ParameterInstance[] parameters = autoRequest.getInputParameters();
		boolean suceeded;
		if (parameters.length == 0) {
			suceeded = project.scheduleBuild(cause);
		} else {
		    List<ParameterValue> values = getParameterValues(project, parameters);
		    suceeded = project.scheduleBuild2(project.getQuietPeriod(), cause, new ParametersAction(values)) != null;
		}

		if (!suceeded) {
			// Build already queued.
			LOG.log(Level.WARNING, "Automation request rejected (409 conflict) since build is already queued: " + jobName);
			throw HttpResponses.status(HttpServletResponse.SC_CONFLICT);
		}

		URI requestURI = getAutoRequestURI(request, job, nextBuildNumber);
		response.setStatus(HttpServletResponse.SC_CREATED);
		response.setHeader("Location", requestURI.toString());
	}

	private List<ParameterValue> getParameterValues(AbstractProject<?, ?> project, ParameterInstance[] parameters) {
	    ParametersDefinitionProperty pp = project.getProperty(ParametersDefinitionProperty.class);
	    if (pp == null) {
	    	LOG.log(Level.FINE, "Job does not take parameters: " + project.getName());
	    	throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST); // This build is not parameterized.
	    }
	    
	    HashMap<String, String> inputMap = new HashMap<String, String>();
	    for (ParameterInstance param : parameters) {
	    	inputMap.put(param.getName(), param.getValue());
	    }

	    List<ParameterValue> values = new ArrayList<ParameterValue>();
	    for (ParameterDefinition def : pp.getParameterDefinitions()) {
	    	String inputValue = inputMap.get(def.getName());
	    	if (inputValue == null) {
	    		ParameterValue defaultValue = def.getDefaultParameterValue();
	    		if (defaultValue == null) {
	    			LOG.log(Level.FINE, "Missing parameter " + def.getName() + " for job " + project.getName());
	    			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
	    		}
	    		
	    		values.add(defaultValue);
	    	} else {
	    		if (def instanceof SimpleParameterDefinition) {
	    			SimpleParameterDefinition simple = (SimpleParameterDefinition) def;
	    			values.add(simple.createValue(inputValue));
	    		} else {
	    			LOG.log(Level.WARNING, "Unsupported parameter type with name " + def.getName() + " for project " + project.getName());
	    			throw HttpResponses.status(HttpServletResponse.SC_NOT_IMPLEMENTED);
	    		}
	    	}
	    }

	    return values;
    }

	public AutomationPlan toAutomationPlan(StaplerRequest request, Job<?, ?> job) throws URISyntaxException {
		AutomationPlan plan = new AutomationPlan();
		plan.setAbout(getJobURI(request, job));
		plan.setTitle(job.getDisplayName());
		plan.setDescription(job.getDescription());
		plan.setServiceProvider(getProviderURI(request));
		
		if (job instanceof AbstractProject) {
			AbstractProject<?, ?> project = (AbstractProject<?, ?>) job;
			fillInParameters(request, plan, project);
		}

		return plan;
	}

	private void fillInParameters(StaplerRequest request, AutomationPlan plan, AbstractProject<?, ?> project) throws URISyntaxException {
	    ParametersDefinitionProperty pp = project.getProperty(ParametersDefinitionProperty.class);
	    if (pp == null) {
	    	return;
	    }

	    Property[] autoParams = new Property[pp.getParameterDefinitions().size()];
	    int i = 0;
	    for (ParameterDefinition def : pp.getParameterDefinitions()) {
	    	autoParams[i++] = toProperty(request, def);
	    }
	
	    plan.setParameterDefinitions(autoParams);
    }

	private Property toProperty(StaplerRequest request, ParameterDefinition def) throws URISyntaxException {
	    Property prop = new Property();
	    prop.setName(def.getName());
	    prop.setDescription(def.getDescription());
	    
	    if (def instanceof BooleanParameterDefinition) {
	    	prop.setValueType(new URI(XSDDatatype.XSDboolean.getURI()));
	    } else if (def instanceof StringParameterDefinition || def instanceof PasswordParameterDefinition) {
	    	prop.setValueType(new URI(XSDDatatype.XSDstring.getURI()));
	    } else if (def instanceof ChoiceParameterDefinition) {
	    	prop.setValueType(new URI(XSDDatatype.XSDstring.getURI()));
	    	ChoiceParameterDefinition choices = (ChoiceParameterDefinition) def;
	    	prop.setAllowedValuesCollection(choices.getChoices());
	    }
	    // TODO: Other types?
	
	    ParameterValue defaultValue = def.getDefaultParameterValue();
	    if (defaultValue == null) {
	    	prop.setOccurs(Occurs.ExactlyOne);
	    } else {
	    	prop.setOccurs(Occurs.ZeroOrOne);
	    	if (!defaultValue.isSensitive()) {
	    		if (defaultValue instanceof BooleanParameterValue) {
	    			BooleanParameterValue bool = (BooleanParameterValue) defaultValue;
	    			prop.setDefaultValue(bool.value);
	    		} else if (defaultValue instanceof StringParameterValue) {
	    			StringParameterValue str = (StringParameterValue) defaultValue;
	    			prop.setDefaultValue(str.value);
	    		}
		    	// TODO: Other types?
	    	}
	    }

	    return prop;
    }

	private void requireGET(StaplerRequest request) {
		requireMethod(request, "GET");
	}

	private void requirePOST(StaplerRequest request) {
		requireMethod(request, "POST");
	}

	private void requireMethod(StaplerRequest request, String method) {
		if (!method.equals(request.getMethod())) {
			throw HttpResponses.status(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		}
	}

	private WhereClause parseWhere(String where, String prefixes) {
		final Map<String, String> prefixMap;
		if (prefixes == null) {
			prefixMap = PREFIX_MAP;
		} else {
			try {
				prefixMap = QueryUtils.parsePrefixes(prefixes);
			} catch (ParseException e) {
				LOG.log(Level.FINE, "Bad oslc.prefix", e);
				throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
			}
		}

		try {
			return QueryUtils.parseWhere(where, prefixMap);
		} catch (ParseException e) {
			LOG.log(Level.FINE, "Bad oslc.where", e);
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}
	}

	private URI getJobURI(StaplerRequest request, Job<?, ?> job) {
		return getBaseUriBuilder(request).path(PATH_JOB).path(job.getName()).build();
	}

	private URI getJobPreviewURI(StaplerRequest request, Job<?, ?> job) {
		return getBaseUriBuilder(request).path(PATH_JOB).path(job.getName()).path(PATH_PREVIEW).build();
	}

	private String getJobNameFromURI(StaplerRequest request, URI uri)
	        throws UnsupportedEncodingException {
		String uriString = uri.toString();
		String rootPath = request.getRootPath() + "/";
		if (!uriString.startsWith(rootPath)) {
			return null;
		}

		String segments[] = uriString.substring(rootPath.length()).split("/");
		if (segments.length != 3 || !PATH_AUTO.equals(segments[0]) || !PATH_JOB.equals(segments[1])) {
			return null;
		}

		return URLDecoder.decode(segments[2], "UTF-8");
	}

	@SuppressWarnings("rawtypes")
	public void doQueryRuns(StaplerRequest request, StaplerResponse response,
	        @QueryParameter("oslc.where") String where, @QueryParameter("oslc.prefix") String prefixes) throws IOException,
	        URISyntaxException {
		requireGET(request);
		WhereClause whereClause = null;
		if (where != null) {
			whereClause = parseWhere(where, prefixes);
		}

		Collection<Job> jobs = Hudson.getInstance().getItems(Job.class);
		ArrayList<AutomationResult> results = new ArrayList<AutomationResult>();

		for (Job<?, ?> job : jobs) {
			if (jobMatchesRunWhereClause(request, job, whereClause)) {
				Iterator<?> i = job.getBuilds().iterator();
				while (i.hasNext()) {
					Run<?, ?> run = (Run<?, ?>) i.next();
					results.add(toAutomationResult(request, job, run));
				}
			}
		}

		marshalQueryResult(request, response, results);
	}

	private boolean jobMatchesRunWhereClause(StaplerRequest request, Job<?, ?> job, WhereClause whereClause) {
		if (whereClause == null) {
			return true;
		}

		for (SimpleTerm term : whereClause.children()) {
			PName pname = term.property();
			String prop = pname.namespace + pname.local;
			if (prop.equals(AutomationConstants.AUTOMATION_NAMESPACE + "reportsOnAutomationPlan")
			        && !uriMatches(getJobURI(request, job), term)) {
				return false;
			}
		}

		return true;
	}

	private boolean uriMatches(URI actual, SimpleTerm term) {
		switch (term.type()) {
		case COMPARISON:
			return uriMatchesComparison(actual, (ComparisonTerm) term);
		case IN_TERM:
			return uriMatchesInTerm(actual, (InTerm) term);
		case NESTED:
			throw HttpResponses.status(HttpServletResponse.SC_NOT_IMPLEMENTED);
		default:
			return true;
		}
	}

	private boolean uriMatchesInTerm(URI actual, InTerm in) {
		String actualString = actual.toString();

		for (Object element : in.values()) {
			Value value = (Value) element;
			if (!(value instanceof UriRefValue)) {
				throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
			}

			UriRefValue uriRef = (UriRefValue) value;
			String uri = uriRef.value();
			if (uri.equals(actualString)) {
				return true;
			}
		}

		return false;
	}

	private boolean uriMatchesComparison(URI actual, ComparisonTerm comparison) {
		String actualString = actual.toString();
		Value value = comparison.operand();
		if (!(value instanceof UriRefValue)) {
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}
		UriRefValue uriRef = (UriRefValue) value;
		String uri = uriRef.value();
		switch (comparison.operator()) {
		case EQUALS:
			return actualString.equals(uri);
		case NOT_EQUALS:
			return !actualString.equals(uri);
		default:
			throw HttpResponses.status(HttpServletResponse.SC_BAD_REQUEST);
		}
	}

	private AutomationResult toAutomationResult(StaplerRequest request, Job<?, ?> job, Run<?, ?> run) throws URISyntaxException {
		AutomationResult result = new AutomationResult();
		result.setAbout(getRunURI(request, job, run));
		result.setIdentifier(run.getId());
		result.setServiceProvider(getProviderURI(request));
		result.setTitle(run.getFullDisplayName());

		Result hudsonResult = run.getResult();
		if (hudsonResult == Result.SUCCESS) {
			result.addState(new URI(AutomationConstants.STATE_COMPLETE));
			result.addVerdict(new URI(AutomationConstants.VERDICT_PASSED));
		} else if (hudsonResult == Result.FAILURE) {
			result.addState(new URI(AutomationConstants.STATE_COMPLETE));
			result.addVerdict(new URI(AutomationConstants.VERDICT_FAILED));
		} else if (hudsonResult == Result.NOT_BUILT) {
			result.addState(new URI(AutomationConstants.STATE_CANCELED));
		} else if (hudsonResult == Result.ABORTED) {
			result.addState(new URI(AutomationConstants.STATE_CANCELED));
		} else if (hudsonResult == Result.UNSTABLE) {
			result.addState(new URI(AutomationConstants.STATE_COMPLETE));
			result.addVerdict(new URI(AutomationConstants.VERDICT_WARNING));
		}

		URI jobURI = getJobURI(request, job);
		Link jobLink = new Link(jobURI, job.getDisplayName());
		result.setReportsOnAutomationPlan(jobLink);

		return result;
	}

	private AutomationRequest toAutomationRequest(StaplerRequest request,
	        Job<?, ?> job, Run<?, ?> run) {
		AutomationRequest autoRequest = new AutomationRequest(getAutoRequestURI(request, job, run));

		URI jobURI = getJobURI(request, job);
		Link jobLink = new Link(jobURI, job.getDisplayName());
		autoRequest.setExecutesAutomationPlan(jobLink);

		return autoRequest;
	}

	private URI getRunURI(StaplerRequest request, Job<?, ?> job, Run<?, ?> run) {
		return getBaseUriBuilder(request).path(PATH_JOB).path(job.getName())
		        .path(PATH_RUN).path("" + run.getNumber()).build();
	}

	private URI getRunPreviewURI(StaplerRequest request, Job<?, ?> job, Run<?, ?> run) {
		return getBaseUriBuilder(request).path(PATH_JOB).path(job.getName())
		        .path(PATH_RUN).path("" + run.getNumber()).path(PATH_PREVIEW)
		        .build();
	}

	private URI getAutoRequestURI(StaplerRequest request, Job<?, ?> job, Run<?, ?> run) {
		return getAutoRequestURI(request, job, run.getNumber());
	}

	private URI getAutoRequestURI(StaplerRequest request, Job<?, ?> job,
	        int buildNumber) {
		return getBaseUriBuilder(request).path(PATH_JOB).path(job.getName())
		        .path(PATH_RUN).path("" + buildNumber).path(PATH_REQUEST)
		        .build();
	}

	private UriBuilder getBaseUriBuilder(StaplerRequest request) {
		return UriBuilder.fromPath(request.getRootPath()).path(PATH_AUTO);
	}

	private URI getProviderURI(StaplerRequest request) {
		return getBaseUriBuilder(request).path("provider").build();
	}

	private static String getFullRequestURI(StaplerRequest request) {
		StringBuffer requestURL = request.getRequestURL();
		String queryString = request.getQueryString();
		if (queryString == null) {
			return requestURL.toString();
		} else {
			return requestURL.append('?').append(queryString).toString();
		}
	}

	private void marshalQueryResult(StaplerRequest request,
	        StaplerResponse response, Collection<? extends Object> resources) throws IOException,
	        URISyntaxException {
		QueryResponse queryResponse = new QueryResponse();
		queryResponse.setAbout(new URI(request.getRequestURL().toString()));
		queryResponse.setResources(resources);

		ResponseInfo responseInfo = new ResponseInfo();
		String uri = getFullRequestURI(request);
		responseInfo.setAbout(new URI(uri));
		responseInfo.setTotalCount(resources.size());

		Object objects[] = { responseInfo, queryResponse };
		marshal(request, response, objects);
	}

	private void marshal(StaplerRequest request, StaplerResponse response,
	        Object object) throws IOException {
		marshal(request, response, new Object[] { object });
	}

	private void marshal(StaplerRequest request, StaplerResponse response,
	        Object objects[]) throws IOException {
		OSLC4JMarshaller marshaller = OSLC4JContext.newInstance().createMarshaller();

		MediaType type = AcceptUtil.matchMediaType(request);
		if (type == null) {
			throw HttpResponses.status(HttpServletResponse.SC_NOT_ACCEPTABLE);
		}

		marshaller.setMediaType(type);

		response.setCharacterEncoding("UTF-8");
		response.setHeader("OSLC-Core-Version", "2.0");
		response.setHeader("Content-Type", type.toString());
		response.setHeader("Vary", "Accept, Accept-Encoding");

		// Use WriterOutputStream since Stapler has already called response.getWriter().
		WriterOutputStream out = new WriterOutputStream(response.getWriter());
		marshaller.marshal(objects, out);
	}
}
