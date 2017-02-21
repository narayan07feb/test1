package com.optum.ogn.controller;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.map.HashedMap;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.mdm.port.party.GetSuspectBySuspectIdOutputType;
import com.migcomponents.migbase64.Base64;
import com.optum.ogn.app.AppConstants;
import com.optum.ogn.app.ConnectionSettings;
import com.optum.ogn.app.ExternalIntegrationConfiguration;
import com.optum.ogn.captcha.CaptchaValidator;
import com.optum.ogn.configuration.SiteminderPortalDefaultSettingUtil;
import com.optum.ogn.domain.healthsafe.UserSecurityQuestions;
import com.optum.ogn.eligibilityschema.PortalDestinationType;
import com.optum.ogn.iam.model.AddUserResponse;
import com.optum.ogn.iam.model.ChallengeResponseQuestion;
import com.optum.ogn.iam.model.Device;
import com.optum.ogn.iam.model.EmailAddress;
import com.optum.ogn.iam.model.Error;
import com.optum.ogn.iam.model.ErrorMessage;
import com.optum.ogn.iam.model.Errors;
import com.optum.ogn.iam.model.IdentificationData;
import com.optum.ogn.iam.model.PhoneNumber;
import com.optum.ogn.iam.model.PhoneNumber.LabelEnum;
import com.optum.ogn.iam.model.Resource;
import com.optum.ogn.iam.model.Resources;
import com.optum.ogn.iam.model.Response;
import com.optum.ogn.iam.model.SecurityQuestionAndAnswer;
import com.optum.ogn.iam.model.UserDetail;
import com.optum.ogn.iam.model.UserPayload;
import com.optum.ogn.model.AddDeviceResponse;
import com.optum.ogn.model.AddUserRequest;
import com.optum.ogn.model.AuthenticationStatus;
import com.optum.ogn.model.CaptchaAttempts;
import com.optum.ogn.model.CheckUserNameResponse;
import com.optum.ogn.model.CheckUserNameResponse.StatusEnum;
import com.optum.ogn.model.InboundParameterUIData;
import com.optum.ogn.model.LoginAttempt;
import com.optum.ogn.model.MyuhcMemberRequest;
import com.optum.ogn.model.PortalSetting;
import com.optum.ogn.model.SMSAuthorizationResponse;
import com.optum.ogn.model.SMSVerficationModel;
import com.optum.ogn.model.SecurityContextDataModel;
import com.optum.ogn.model.SessionInfoWrapper;
import com.optum.ogn.model.VoiceAuthorizationResponse;
import com.optum.ogn.provision.model.GetMemberAttrResponse;
import com.optum.ogn.service.HealthSafeIdService;
import com.optum.ogn.service.MyuhcMemberEligibilityService;
import com.optum.ogn.service.ProvisionDataStoreService;
import com.optum.ogn.util.AuthenticationHelper;
import com.optum.ogn.util.CryptoUtil;
import com.optum.ogn.util.EmailValidator;
import com.optum.ogn.util.UIRequestValidator;
import com.optum.ogn.util.URLHelper;

import sun.misc.BASE64Encoder;

@Controller
public class HealthSafeIdLoginController extends ScopeBasedController {

	private Logger logger = Logger.getLogger(HealthSafeIdLoginController.class.getName());

	@Autowired
	private LoginAttempt loginAttempt;

	@Autowired
	private CaptchaAttempts captchaAttempts;

	@Inject
	private HttpServletRequest request;

	@Inject
	private HttpServletResponse response;

	@Inject
	private HttpSession httpSession;

	@Inject
	private SessionValidationController validationController;

	@Inject
	private ContentController contentController;

	@Inject
	private AuthenticationController authenticationController;

	@Inject
	private ExternalIntegrationConfiguration externalIntegrationConfiguration;

	@Inject
	private HealthSafeIdService healthSafeIdService;

	@Inject
	private ProvisionDataStoreService provisionDataStoreService;

	@Inject
	private MyuhcMemberEligibilityService myuhcService;

	@Value("${clients.iam.resource.voiceCallChallenge}")
	private String voiceCallChallenge;

	@Value("${clients.iam.resource.voiceCallStatus}")
	private String voiceCallStatus;

	@Value("${clients.iam.resource.resetPasswordUrl}")
	private String resetPasswordUrl;

	@Value("${clients.iam.resource.emailToken}")
	private String emailToken;

	public static final String ACCEPT_HEADER_NAME = "accept";

	public static final String ACCEPT_CHARSET_HEADER_NAME = "accept-charset";

	public static final String ACCEPT_ENCODING_HEADER_NAME = "accept-encoding";

	public static final String ACCEPT_LANGUAGE_HEADER_NAME = "accept-language";

	public static final String REFERER_HEADER_NAME = "REFERER";

	public static final String USER_AGENT_HEADER_NAME = "user-agent";

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.setDisallowedFields(new String[] {});
	}

	/*******************************************************************************************************************
	 * Start of Services Endpoint
	 *******************************************************************************************************************/

	@RequestMapping(value = "/protected/user/rsa", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Map<String, Boolean> isRSALocked(@RequestParam(value = "ids", required = true) String ids) {
		logger.info("In /protected/user/list");
		Map<String, Boolean> oResponse = null;
		oResponse = healthSafeIdService.getLockStatus(ids);
		return oResponse;
	}

	@RequestMapping(value = "/protected/admin/account/email", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendEmailFromAdmin(@RequestParam(value = "to", required = true) String email,
			@RequestParam(value = "userid", required = false, defaultValue = "") String userid,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String language,
			@RequestParam(value = AppConstants.OPTUMID_ACTION, required = true) String action

	) {
		if (StringUtils.isEmpty(language) || StringUtils.equalsIgnoreCase(language, "null")) {
			language = getLang(sessionInfo());
		}
		logger.info("In /protected/admin/account/email/" + action);
		String url = new StringBuilder(ConnectionSettings.getIamServer())
				.append(ConnectionSettings.getIAMEmailResource()).append("/").append(action).append("?to=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(email))).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).append("&")
				.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
				.append(StringUtils.isEmpty(language) || "null".equalsIgnoreCase(language) ? "en" : language)
				.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=").append(targetPortal)
				.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
				.toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		return content;
	}

	@RequestMapping(value = "/protected/device", method = { RequestMethod.POST }, produces = { "application/json" })
	@ResponseBody
	public Object updateUserDevice(@RequestBody Map<String, String> payLoad) {
		String userId = null;
		if (sessionInfo().getSecurityContext() != null
				&& StringUtils.isNotBlank(sessionInfo().getSecurityContext().getPrivilegedUserid())
				&& sessionInfo().getSecurityContext().isUserInRegistrationScreen()
				&& sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration() && payLoad != null
				&& payLoad.get("device") != null) {
			userId = sessionInfo().getSecurityContext().getPrivilegedUserid();
			try {
				rememberUserDevice(payLoad.get("device"), userId, null);
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("200");
				error.setDescription("Successfully added user device");
				return error;
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Error");
				return error;
			}
		}
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("400");
		error.setDescription("Bad Request");
		return error;
	}

	@RequestMapping(value = "/protected/admin/account/rba/unlock", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public Object unlockRBAUser(@RequestParam(value = "userid", required = false) String userid,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {
		logger.info("In /protected/admin/account/rba/unlock");
		String responseString = null;
		Response oResponse = null;
		AddUserRequest addUserRequest = new AddUserRequest();
		try {
			List<SecurityQuestionAndAnswer> securityQuestionAndAnswerList = new ArrayList<SecurityQuestionAndAnswer>();
			addUserRequest.setSecurityQuestionAndAnswers(securityQuestionAndAnswerList);
			responseString = healthSafeIdService.getSecureUserList(userid).get();
			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			oResponse = mapper.readValue(responseString, Response.class);
			if (oResponse != null && StringUtils.equalsIgnoreCase(oResponse.getStatus().toString(), "SUCCESS")
					&& oResponse.getInfo() == null) {
				Resources resources = oResponse.getResources();
				if (resources != null && resources.getResource() != null && resources.getResource().size() > 0) {
					Resource resource = resources.getResource().get(0);
					IdentificationData identificationData = resource.getUserIdentificationData();
					if (identificationData != null) {
						addUserRequest.setUuid(new String(identificationData.getUUID().getValue()));
						addUserRequest.setUserName(new String(identificationData.getUserName().getValue()));
						// logger.info("in /secure/user/list uuid:
						// "+sessionInfo().getUnAuthenticatedUUID());
						// logger.info("in /secure/user/list userid: "+optumId);
						identificationData.setUUID(null);
					}
					UserPayload userPayload = resource.getUserPayload();
					if (userPayload != null) {
						// logger.info("firstName :"+
						// resource.getUserPayload().getFirstName()+"lastName:
						// "+ resource.getUserPayload().getLastName());
						UserDetail userDetail = userPayload.getUserDetail();
						List<PhoneNumber> phoneNumbersList = userDetail.getPhoneNumbers();
						if (phoneNumbersList != null && phoneNumbersList.size() > 0) {

							for (PhoneNumber phoneNumber : phoneNumbersList) {
								// logger.info("in /secure/user/list
								// phoneNumber.getAreaCode()+phoneNumber.getAreaCode():
								// "+phoneNumber.getAreaCode()+phoneNumber.getAreaCode());
								addUserRequest.setAreaCode(phoneNumber.getAreaCode());
								addUserRequest.setNumber(phoneNumber.getNumber());
								addUserRequest.setPhoneType(phoneNumber.getLabel().toString());
								// logger.info("in /secure/user/list
								// sessionInfo().getMobileNumber():
								// "+sessionInfo().getMobileNumber());
							}
						}
						List<EmailAddress> emailAddressList = userPayload.getEmails();
						if (userDetail.getCredential() != null) {
							List<ChallengeResponseQuestion> ChallengeResponseQuestionList = userDetail.getCredential()
									.getSecurityQuestionAndAnswers();
							if (ChallengeResponseQuestionList != null && ChallengeResponseQuestionList.size() > 0) {
								for (ChallengeResponseQuestion challengeResponseQuestion : ChallengeResponseQuestionList) {
									SecurityQuestionAndAnswer securityQuestionAndAnswer = new SecurityQuestionAndAnswer();
									securityQuestionAndAnswer.setId(challengeResponseQuestion.getId());
									securityQuestionAndAnswer.setAnswer(challengeResponseQuestion.getAnswer());
									securityQuestionAndAnswer.setQuestion(challengeResponseQuestion.getQuestion());
									securityQuestionAndAnswerList.add(securityQuestionAndAnswer);
								}
							}
						}
						if (emailAddressList != null && emailAddressList.size() > 0) {
							for (EmailAddress emailAddress : emailAddressList) {
								if (StringUtils.equalsIgnoreCase("Primary", emailAddress.getLabel().toString()))
									addUserRequest.setPrimaryEmail(new String(emailAddress.getValue()));
								// logger.info("in /secure/user/list
								// sessionInfo().getEmail():
								// "+sessionInfo().getEmail());
							}
						}
					}
				}
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			e.printStackTrace();
		}

		try {
			return healthSafeIdService.unlockRBAUser(addUserRequest).get();
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return oResponse;
	}

	@RequestMapping(value = "/protected/obscene", method = { RequestMethod.POST }, produces = { "application/json" })
	@ResponseBody
	public Map<String, String> isObscene(@RequestBody Map<String, String> payLoad) {

		Map<String, String> resulstList = new HashMap<String, String>();

		if (payLoad != null && payLoad.size() > 0) {
			for (Map.Entry<String, String> entry : payLoad.entrySet()) {
				resulstList.put(entry.getKey(), AppConstants.isObsceneWord(entry.getValue()) + "");
			}
			return resulstList;
		}
		resulstList.put("code", "400");
		resulstList.put("description", "request should not be empty");
		return resulstList;
	}

	/*
	 * @RequestMapping(value = "/protected/account/email/token", method =
	 * {RequestMethod.GET}, produces = {"application/json"})
	 * 
	 * @ResponseBody public String getEmailToken(@RequestParam(value= "to",
	 * required = true) String email,
	 * 
	 * @RequestParam(value= "userid", required = true) String userid) {
	 * logger.info("In /protected/account/email/verf/token");
	 * 
	 * String url = new
	 * StringBuilder(ConnectionSettings.getIamServer()).append(emailToken)
	 * .append("?to=").append(java.net.URLEncoder.encode(email)).append(
	 * "&userid=").append(userid).toString(); String content =
	 * ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
	 * logger.info("In /protected/account/email/verf/token content: "+content);
	 * return content; }
	 */

	@RequestMapping(value = "/protected/admin/email/password", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public void pwdReset(@RequestParam(value = "to", required = false, defaultValue = "") String mail,
			@RequestParam(value = "resetPassword", required = true) String resetPassword,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = false) String targetUrl,
			@RequestParam(value = AppConstants.HTTP_ADMIN_TARGETPORTAL, required = false) String brandPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {
		logger.info("In /protected/email/password service sending resetpassword email");

		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(resetPasswordUrl)
				.append("?HTTP_TARGETPORTAL=").append(targetPortal).append("&HTTP_TARGETURL=").append(targetUrl)
				.append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
				.append(StringUtils.isEmpty(lang) || "null".equalsIgnoreCase(lang) ? "en" : lang)
				.append("&HTTP_ERRORURL=").append(errorUrl).append("&HTTP_ACCESSTYPE=").append(accessType)
				.append("&HTTP_BRANDPORTAL=").append(AppConstants.getPortalBrand(targetUrl)).append("&HTTP_ACCESSCODE=")
				.append(accessCode).append("&").append(AppConstants.OPTUMID_HEADER_BRANDURL).append("=")
				.append(brandUrl).append("&to=").append(java.net.URLEncoder.encode(StringUtils.defaultString(mail)))
				.toString();
		ConnectionSettings.getRestClient(url).getAsJson(String.class);

	}

	@RequestMapping(value = "/secure/ping", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public String ping(@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String userId) {

		return "{\"status\": \"success\"}";
	}

	@RequestMapping(value = "/protected/inbound", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public InboundParameterUIData getInboundUIData() {

		if (sessionInfo().getInboundParameter() != null) {
			return new InboundParameterUIData(sessionInfo().getInboundParameter());
		}

		return null;
	}

	@RequestMapping(value = "/secure/profile", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Map<String, Boolean> getProfile(
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String optumId) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		logger.info("In /protected/profile");
		Map<String, Boolean> profile = new HashedMap();
		try {
			if (StringUtils.isBlank(optumId)) {
				response.setStatus(HttpStatus.BAD_REQUEST.value());
			} else {
				profile = healthSafeIdService.getProfileById(optumId).get();
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}

		return profile;
	}

	@RequestMapping(value = "/protected/admin/user/enablement", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object lockUser(@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String userId,
			@RequestHeader(value = "hsid_admin_searchkey", required = false) String searchkey,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		try {

			logger.info("In /protected/user/enablement service sending lockUser email");
			if (StringUtils.isNotBlank(searchkey)) {
				userId = new String(searchkey);
			}
			if (StringUtils.isBlank(userId)) {
				response.setStatus(HttpStatus.BAD_REQUEST.value());
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("400");
				error.setDescription("Userid not found");
				return error;
			} else {
				return healthSafeIdService.lockUser(userId).get();
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("500");
		error.setDescription("Internal Server Exception");
		return error;
	}

	@RequestMapping(value = "/protected/profile/question", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object updateSecurityQuesDuringReg(@RequestBody UserSecurityQuestions userSecurityQuestions,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal) {
		String userId = null;
		if (sessionInfo().getSecurityContext() != null
				&& StringUtils.isNotBlank(sessionInfo().getSecurityContext().getPrivilegedUserid())
				&& sessionInfo().getSecurityContext().isUserInRegistrationScreen()
				&& sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			userId = sessionInfo().getSecurityContext().getPrivilegedUserid();

		}
		return addUserSQ(userId, userSecurityQuestions, targetPortal);
	}

	@RequestMapping(value = "/protected/profile/{userprofile}", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object updateUserPhoneandEmail(@PathVariable("userprofile") String userProfile,
			@RequestBody Map<String, String> payLoad,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal,
			@RequestParam(value = "source", required = false) String source,
			@RequestParam(value = AppConstants.HTTP_ADMIN_TARGETPORTAL, required = false) String adminTargetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {

		if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null")) {
			lang = getLang(sessionInfo());
		}

		String userId = null;
		if ((StringUtils.equalsIgnoreCase(userProfile, "email") || StringUtils.equalsIgnoreCase(userProfile, "phone")
				|| StringUtils.equalsIgnoreCase(userProfile, "question")) && sessionInfo().getSecurityContext() != null
				&& StringUtils.isNotBlank(sessionInfo().getSecurityContext().getPrivilegedUserid())
				&& sessionInfo().getSecurityContext().isUserInRegistrationScreen()
				&& sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			userId = sessionInfo().getSecurityContext().getPrivilegedUserid();

		}
		if (sessionInfo().getSecurityContext() != null
				&& StringUtils.isNotBlank(sessionInfo().getSecurityContext().getPrivilegedUserid())
				&& (sessionInfo().getSecurityContext().isSecurityQuestionsValidated()
						|| sessionInfo().getSecurityContext().isPhoneNumberVerified())) {
			userId = sessionInfo().getSecurityContext().getPrivilegedUserid();

		}
		// logger.info("In /protected/profile/"+ userProfile+" userId:
		// "+userId);
		// logger.info("In /protected/profile/"+ userProfile+"
		// isPhoneNumberVerified: "+
		// sessionInfo().getSecurityContext().isPhoneNumberVerified());
		// logger.info("In /protected/profile/"+ userProfile+"
		// isSecurityQuestionsValidated: "+
		// sessionInfo().getSecurityContext().isSecurityQuestionsValidated());
		// logger.info("In /protected/profile/"+ userProfile+"
		// isUserInRegistrationScreen: "+
		// sessionInfo().getSecurityContext().isUserInRegistrationScreen());
		return updateUserProfile(userProfile, payLoad, userId, targetPortal, source, adminTargetPortal, null,
				getLang(sessionInfo()));
	}

	@RequestMapping(value = "/secure/profile/{userprofile}", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object updateLoggedinUserPhoneandEmail(
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String optumId,
			@PathVariable("userprofile") String userProfile, @RequestBody Map<String, String> payLoad,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal,
			@RequestParam(value = "source", required = false) String source,
			@RequestParam(value = AppConstants.HTTP_ADMIN_TARGETPORTAL, required = false) String adminTargetPortal) {
		String userId = null;
		if (StringUtils.isNotBlank(optumId)) {
			userId = optumId;
		}
		return updateUserProfile(userProfile, payLoad, userId, targetPortal, source, adminTargetPortal, null,
				getLang(sessionInfo()));
	}

	@RequestMapping(value = "/protected/admin/profile/{userprofile}", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object updaterUserProfileAsAdmin(@PathVariable("userprofile") String userProfile,
			@RequestBody Map<String, String> payLoad,
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String userId,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal,
			@RequestParam(value = "source", required = false) String source,
			@RequestParam(value = AppConstants.HTTP_ADMIN_TARGETPORTAL, required = false) String adminTargetPortal,
			@RequestHeader(value = "hsid_admin_searchkey", required = false) String searchkey,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {

		if (StringUtils.contains(userProfile, "key")) {
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("400");
			error.setDescription("Admin dont have rights to reset user password");
			return error;
		}
		return updateUserProfile(userProfile, payLoad, userId, targetPortal, source, adminTargetPortal, searchkey,
				StringUtils.isEmpty(lang) || "null".equalsIgnoreCase(lang) ? "en" : lang);
	}

	public Object updateUserProfile(String userProfile, Map<String, String> payLoad, String userId, String targetPortal,
			String source, String adminTargetPortal, String searchkey, String lang) {
		String portalBrand = adminTargetPortal;
		if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null"))
			lang = getLang(sessionInfo());
		logger.info("In /protected/profile/");
		if (sessionInfo().getInboundParameter() != null && StringUtils.isBlank(portalBrand)) {
			portalBrand = AppConstants.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());
		}
		if (StringUtils.isNotBlank(searchkey)) {
			userId = new String(searchkey);
		}
		if (StringUtils.isBlank(userId)) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("400");
			error.setDescription("Userid not found");
			return error;
		}

		if (StringUtils.equalsIgnoreCase(userProfile, "name")) {

			if (payLoad == null || StringUtils.isBlank(payLoad.get("firstName"))
					|| StringUtils.isBlank(payLoad.get("lastName"))) {
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("400");
				error.setDescription("missing either firstName or lastName");
				return error;
			}
			try {

				return healthSafeIdService.updateName(userProfile, payLoad, userId, targetPortal, portalBrand, lang)
						.get();
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("500");
			error.setDescription("Internal Server Exception");
			return error;
		} else if (StringUtils.equalsIgnoreCase(userProfile, "key")) {

			if (payLoad != null && payLoad.containsKey("newpassword")) {

				try {
					Map<String, Boolean> userInfo = healthSafeIdService.getUserSQ(userId).get();
					if (userInfo != null && userInfo.size() > 0) {
						Boolean isUserLocked = userInfo.get("isUserLocked");
						if (!isUserLocked) {
							healthSafeIdService.lockUser(userId);
						}
					}
				} catch (InterruptedException | ExecutionException e) {
					e.printStackTrace();
				}

				try {

					Object error = healthSafeIdService
							.setPassword(userProfile, payLoad, userId, targetPortal, portalBrand, lang).get();
					if (error != null && error instanceof Error
							&& StringUtils.equalsIgnoreCase(((Error) error).getDescription(), "password id updated")) {
						sessionInfo().setSecurityContext(null);
					}
					return error;
				} catch (InterruptedException | ExecutionException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;

			} else {
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("400");
				error.setDescription("missing either newpassword");
				return error;
			}

		} else if (StringUtils.equalsIgnoreCase(userProfile, "phone")
				|| StringUtils.equalsIgnoreCase(userProfile, "email")) {

			if (payLoad != null && payLoad.get("phone") != null && payLoad.get("phone").matches("\\d{10}")) {
				// logger.info("in call to update user "+
				// sessionInfo().getUnAuthenticatedUserID()+"new phone #: "+
				// payLoad.get("phone"));
				try {
					if (payLoad.get("phone") != null && !StringUtils.equalsIgnoreCase(payLoad.get("type"), "MOBILE")) {
						payLoad.put("type", "HOME");
					}
					Object successError = (Object) healthSafeIdService
							.updateUser(userProfile, payLoad, userId, portalBrand, source, false, lang).get();
					if (successError instanceof com.optum.ogn.iam.model.Error) {

						if (StringUtils.containsIgnoreCase(
								((com.optum.ogn.iam.model.Error) successError).getDescription(), "success")) {
							// logger.info("in call to update user "+
							// sessionInfo().getUnAuthenticatedUserID()+" old
							// phone #: "+ sessionInfo().getMobileNumber());
							// logger.info("after user successfully updated new
							// phone number: "+payLoad.get("phone"));

							sessionInfo().setMobileNumber(payLoad.get("phone"));
							if (StringUtils.equalsIgnoreCase(payLoad.get("type"), "HOME"))
								sessionInfo().setisMobileTypeHome(true);
							// logger.info("in call to update user "+
							// sessionInfo().getUnAuthenticatedUserID()+" new
							// phone #: "+ sessionInfo().getMobileNumber());
						}

					}
					return successError;
				} catch (InterruptedException | ExecutionException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			} else if (payLoad != null && payLoad.get("email") != null
					&& EmailValidator.getInstance().isValid(payLoad.get("email"))) {
				String newEmail = new String(payLoad.get("email"));
				// logger.info("in call to update user "+
				// sessionInfo().getUnAuthenticatedUserID()+"new email #: "+
				// payLoad.get("email"));
				try {
					Object successError = (Object) healthSafeIdService
							.updateUser(userProfile, payLoad, userId, portalBrand, source, false, lang).get();
					if (successError instanceof com.optum.ogn.iam.model.Error) {

						if (StringUtils.containsIgnoreCase(
								((com.optum.ogn.iam.model.Error) successError).getDescription(), "success")) {
							// logger.info("in call to update user "+
							// sessionInfo().getUnAuthenticatedUserID()+" old
							// email #: "+ sessionInfo().getEmail());
							// logger.info("after user successfully updated new
							// email number: "+payLoad.get("email"));

							sessionInfo().setEmail(newEmail);
							// logger.info("in call to update user "+
							// sessionInfo().getUnAuthenticatedUserID()+" new
							// email #: "+ sessionInfo().getEmail());
						}

					}
					return successError;
				} catch (InterruptedException | ExecutionException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			} else {
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("400");
				error.setDescription("phone/email no is not valid");
				return error;
			}

		} else {
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("400");
			error.setDescription(
					"request should be one of {/secure/profile/phone; /secure/profile/email; /secure/profile/key}");
			return error;
		}
	}

	@RequestMapping(value = "/secure/profile/question", method = { RequestMethod.PUT }, produces = {
			"application/json" })
	@ResponseBody
	public Object updateSecurityQues(
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String optumId,
			@RequestBody UserSecurityQuestions userSecurityQuestions,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = false) String targetPortal) {
		logger.info("In /secure/profile/question");
		if (StringUtils.isBlank(optumId)) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("400");
			error.setDescription("Userid not found");
			return error;
		}

		return addUserSQ(optumId, userSecurityQuestions, targetPortal);

	}

	public Object addUserSQ(String optumId, UserSecurityQuestions userSecurityQuestions, String targetPortal) {
		if (userSecurityQuestions != null && userSecurityQuestions.getChallengeResponseQuestions().size() > 0) {

			try {
				if (sessionInfo() != null && sessionInfo().getInboundParameter() != null)
					targetPortal = AppConstants.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());
				return healthSafeIdService.modifyChallengeQue(userSecurityQuestions.getChallengeResponseQuestions(),
						optumId, targetPortal, targetPortal, getLang(sessionInfo())).get();
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}

			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("500");
			error.setDescription("Internal Server Exception");
			return error;

		} else {
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("400");
			error.setDescription("missing either newpassword");
			return error;
		}
	}

	@RequestMapping(value = "/protected/salt", method = { RequestMethod.POST }, produces = { "application/json" })
	@ResponseBody
	public Map<String, String> getBase64Key() {

		Map<String, String> cipherWrapper = new HashedMap();

		try {

			String key = RandomStringUtils.randomAlphanumeric(16).toLowerCase();// "0a1b2c3d4e5f6g7h";//
			String base64Key = (new BASE64Encoder()).encode(key.getBytes("UTF-8"));

			loginAttempt.setBase64Key(key);
			cipherWrapper.put("salt", base64Key);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return cipherWrapper;
	}

	@RequestMapping(value = "/protected/userid", method = { RequestMethod.POST }, produces = { "application/json" })
	@ResponseBody
	public Map<String, String> lookupUserIdByEmail(@RequestBody Map<String, String> emailRequest) {

		Map<String, String> emailWrapper = new HashedMap();
		String email = emailRequest.get("email");
		String userId = email;

		logger.info("In /protected/userid ");

		if (EmailValidator.getInstance().isValid(email)) {
			try {

				Object emailResp = healthSafeIdService.getID(emailRequest).get();
				if ((emailResp instanceof String) && StringUtils.isNotBlank(emailResp.toString())) {
					userId = emailResp.toString();
				} else if ((emailResp instanceof com.optum.ogn.iam.model.Error)
						&& StringUtils.equalsIgnoreCase(((Error) emailResp).getCode(), "404")) {
					emailWrapper.put("code", "404");
					emailWrapper.put("description", "Multiple User Accounts Found, try by adding more filters");
					return emailWrapper;
				}

			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}
		}

		loginAttempt.setCurrentInput(email, userId);

		if (StringUtils.isNotBlank(userId)) {
			try {
				String uuid = healthSafeIdService.getUUIDByUserId(userId).get();

				if (StringUtils.isNotBlank(uuid)) {
					GetMemberAttrResponse enrolledSites = provisionDataStoreService.getEnrolledSiteByUUID(uuid).get();
					if (enrolledSites != null && StringUtils.isNotBlank(enrolledSites.getMdmTermAndConditions())) {
						emailWrapper.put("termsAgreeDate", enrolledSites.getMdmTermAndConditions());
					}
				}

			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}
		}

		if (EmailValidator.getInstance().isValid(email)) {
			String encryptedUserId = CryptoUtil.encryptUIString(userId, loginAttempt.getBase64Key());
			emailWrapper.put("userId_enc", encryptedUserId);
		} else {
			emailWrapper.put("userId", userId);
		}

		return emailWrapper;
	}

	@RequestMapping(value = "/protected/challanges", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Object getChallanges() {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		if ((StringUtils.equalsIgnoreCase(sessionInfo().getInboundParameter().getAccessType(), "TIER1")) && (StringUtils
				.equalsIgnoreCase(sessionInfo().getInboundParameter().getTargetPortal().toString(), "LAWW"))) {
			sessionInfo().getSecurityContext().setMemberEligibileDuringRegistration(true);
		}
		if (!sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			Error error = new Error();
			error.setCode("400");
			error.setDescription("Invalid Request");
			return error;
		}
		Object oResponse = null;
		logger.info("In /protected/challanges");

		try {
			oResponse = healthSafeIdService.getChallenges().get();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}

		return oResponse;
	}

	@RequestMapping(value = "/secure/challanges", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Object getSecureChallanges() {
		Object oResponse = null;
		logger.info("In /secure/challanges");

		try {
			oResponse = healthSafeIdService.getChallenges().get();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}

		return oResponse;
	}

	@RequestMapping(value = "/protected/account/email/{part}", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendEmail(@PathVariable String part,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.HTTP_ADMIN_TARGETPORTAL, required = false) String adminTargetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {

		if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null")) {
			lang = getLang(sessionInfo());
		}

		String email = "";
		try {
			email = healthSafeIdService.getEmailIDfromUserID(sessionInfo().getUnAuthenticatedUserID()).get();
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (StringUtils.isBlank(email)) {
			return "Unable to find email for the given user";
		}
		String portalBrand = adminTargetPortal;
		if (sessionInfo().getInboundParameter() != null && StringUtils.isBlank(portalBrand)) {
			portalBrand = AppConstants.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());
		}
		logger.info("In /protected/account/email/");
		String url = new StringBuilder(ConnectionSettings.getIamServer())
				.append(ConnectionSettings.getIamForgetuserName()).append(part).append("?to=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(email))).append("&username=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(sessionInfo().getUnAuthenticatedUserID())))
				.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
				.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=").append(portalBrand).append("&")
				.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
				.append(StringUtils.isEmpty(lang) || "null".equalsIgnoreCase(lang) ? "en" : lang).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(sessionInfo().getUnAuthenticatedUserID())))
				.toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		if (StringUtils.containsIgnoreCase(content, "ERROR")) {
			return "Unable to send email to the user";
		}
		return "Sent Email Successfully";
	}

	@RequestMapping(value = "/protected/user/list", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Response getFiltedUserInfo(@RequestParam(value = "ids", required = true) String ids) {
		// logger.info("In /protected/user/list isCaptchaValid:
		// "+isCaptchaValid);
		if (!captchaAttempts.isfrgtPwdCaptchaPassed()) {
			Response response = new Response();
			Error error = new Error();
			error.setCode("400");
			error.setDescription("Invalid Captcha String");
			List<Error> list = new ArrayList<Error>();
			list.add(error);
			Errors errors = new Errors();
			errors.setError(list);
			response.setErrors(errors);
			return response;
		}
		logger.info("In /protected/user/list");
		Response oResponse = null;
		try {
			oResponse = healthSafeIdService.getUserFiltereList(ids).get();
			if (oResponse != null && StringUtils.equalsIgnoreCase(oResponse.getStatus().toString(), "SUCCESS")
					&& oResponse.getInfo() == null) {
				Resources resources = oResponse.getResources();
				if (resources != null && resources.getResource() != null && resources.getResource().size() > 0) {

					Resource resource = resources.getResource().get(0);
					IdentificationData identificationData = resource.getUserIdentificationData();
					if (identificationData != null) {
						sessionInfo().setUnAuthenticatedUUID(identificationData.getUUID().getValue());
						sessionInfo().setUnAuthenticatedUserID(new String(identificationData.getUserName().getValue()));
						// logger.info("in protected/user/list uuid:
						// "+sessionInfo().getUnAuthenticatedUUID());
						// logger.info("in protected/user/list userid:
						// "+sessionInfo().getUnAuthenticatedUserID());
						identificationData.setUserName(null);
						identificationData.setUUID(null);

					}
					UserPayload userPayload = resource.getUserPayload();
					if (userPayload != null) {
						// logger.info("firstName :"+
						// resource.getUserPayload().getFirstName()+"lastName:
						// "+ resource.getUserPayload().getLastName());
						UserDetail userDetail = userPayload.getUserDetail();
						List<PhoneNumber> phoneNumbersList = userDetail.getPhoneNumbers();
						if (phoneNumbersList != null && phoneNumbersList.size() > 0) {

							for (PhoneNumber phoneNumber : phoneNumbersList) {
								if (phoneNumber.getLabel().equals(LabelEnum.MOBILE)
										|| phoneNumber.getLabel().equals(LabelEnum.HOME)) {
									// logger.info("in protected/user/list
									// phoneNumber.getAreaCode()+phoneNumber.getAreaCode():
									// "+phoneNumber.getAreaCode()+phoneNumber.getAreaCode());
									sessionInfo().setMobileNumber(
											new String(phoneNumber.getAreaCode() + phoneNumber.getNumber()));
									sessionInfo().setMobileType(phoneNumber.getLabel().toString());
									// logger.info("in protected/user/list
									// sessionInfo().getMobileNumber():
									// "+sessionInfo().getMobileNumber());
									if (sessionInfo().getMobileNumber() != null) {
										phoneNumber.setAreaCode("XXX");
										phoneNumber.setNumber("XXX" + sessionInfo().getMobileNumber().substring(6));
										// logger.info("in protected/user/list
										// phoneNumber after masking:
										// "+phoneNumber.getNumber());
									}

								} else {
									phoneNumber.setAreaCode("XXX");
									phoneNumber.setNumber("XXXXXXXX");
									// logger.info("in protected/user/list
									// phoneNumber after masking:
									// "+phoneNumber.getNumber());
								}
							}
						}
						List<EmailAddress> emailAddressList = userPayload.getEmails();
						if (emailAddressList != null && emailAddressList.size() > 0) {
							for (EmailAddress emailAddress : emailAddressList) {
								if (StringUtils.equalsIgnoreCase("Primary", emailAddress.getLabel().toString()))
									sessionInfo().setEmail(new String(emailAddress.getValue()));
								// logger.info("in protected/user/list
								// sessionInfo().getEmail():
								// "+sessionInfo().getEmail());
							}
						}
						userPayload.setEmails(null);
					}
				}
			}
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}

		return oResponse;
	}

	@RequestMapping(value = "/protected/admin/user/list", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public Response getUsersListforAdmin(@RequestParam(value = "ids", required = true) String ids) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		logger.info("In /protected/user/list");
		Response oResponse = null;
		try {
			oResponse = healthSafeIdService.getAdminUserList(ids).get();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}

		return oResponse;
	}

	@RequestMapping(value = "/protected/admin/account/email/verf", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendAdminEmailVerificationCode(@RequestParam(value = "to", required = true) String email,
			@RequestParam(value = "userid", required = true) String userid,
			@RequestParam(value = "source", required = true) String source,
			@RequestParam(value = "oldEmail", required = false, defaultValue = "") String oldEmail,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = true) String targetUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String language) {

		logger.info("In /protected/account/email/verf");
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamEmailVerf())
				.append("?to=").append(java.net.URLEncoder.encode(StringUtils.defaultString(email))).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).append("&").append("source")
				.append("=").append(source).append("&").append("oldEmail").append("=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(oldEmail))).append("&")
				.append(AppConstants.OPTUMID_HEADER_ACCESSCODE).append("=").append(accessCode).append("&")
				.append(AppConstants.OPTUMID_HEADER_ACCESSTYPE).append("=").append(accessType).append("&")
				.append(AppConstants.OPTUMID_HEADER_TARGETURL).append("=").append(targetUrl).append("&")
				.append(AppConstants.OPTUMID_HEADER_ERRORURL).append("=").append(errorUrl).append("&")
				.append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
				.append(AppConstants.getPortalBrand(targetUrl)).append("&").append(AppConstants.OPTUMID_HEADER_BRANDURL)
				.append("=").append(brandUrl).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
				.append(StringUtils.isEmpty(language) || "null".equalsIgnoreCase(language) ? "en" : language)
				.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
				.toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		logger.info("the value of url before  decoding is " + url.trim());
		logger.info("the value of url after  decoding is " + url.trim().replaceAll(" ", "").replaceAll("&quot;", "\""));
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		return content;
	}

	@RequestMapping(value = "/protected/account/email/verf", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendEmailVerificationCode(@RequestParam(value = "source", required = true) String source,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = true) String targetUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ELIGIBILITY, required = false) String eligibility,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang

	) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		// RestTemplate restTemplate= new RestTemplate();

		// This should be sent from the UI code
		/*
		 * if(sessionInfo().isDestinationMYUHC()) {
		 * targetPortal=sessionInfo().getPortalIndicator().toString();
		 * 
		 * }
		 */
		if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null")) {
			lang = getLang(sessionInfo());
		}
		logger.info("In /protected/account/email/verf");

		/*
		 * String encodedUserId = sessionInfo().getUnAuthenticatedUserID();
		 * logger.info("plain value of userid: "+encodedUserId); try {
		 * encodedUserId =
		 * java.net.URLEncoder.encode(sessionInfo().getUnAuthenticatedUserID(),
		 * "UTF-8"); logger.info("encoded value of userid: "+encodedUserId); }
		 * catch (UnsupportedEncodingException e) { e.printStackTrace(); }
		 */
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamEmailVerf())
				.append("?to=").append(sessionInfo().getEmail()).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(sessionInfo().getUnAuthenticatedUserID())))
				.append("&").append("source").append("=").append(source).append("&")
				.append(AppConstants.OPTUMID_HEADER_ACCESSCODE).append("=").append(accessCode).append("&")
				.append(AppConstants.OPTUMID_HEADER_ACCESSTYPE).append("=").append(accessType).append("&")
				.append(AppConstants.OPTUMID_HEADER_TARGETURL).append("=").append(targetUrl).append("&")
				.append(AppConstants.OPTUMID_HEADER_ERRORURL).append("=").append(errorUrl).append("&")
				.append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
				.append(AppConstants.getPortalBrand(targetUrl)).append("&").append(AppConstants.OPTUMID_HEADER_BRANDURL)
				.append("=").append(brandUrl).append("&").append(AppConstants.OPTUMID_HEADER_ELIGIBILITY).append("=")
				.append(eligibility).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
				.append(getLang(sessionInfo())).append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=")
				.append(targetPortal).toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		logger.info("In /protected/account/email/verf ");
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		if (StringUtils.containsIgnoreCase(content, "SUCCESS")) {
			return "{" + "\"" + "status" + "\"" + ":" + "\"" + "SUCCESS" + "\"}";
		}
		return content;
	}

	@RequestMapping(value = "/protected/admin/account/phone/auth", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendPhoneAuthorizationCode(@RequestParam(value = "token", required = true) String token) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		// RestTemplate restTemplate= new RestTemplate();
		logger.info("In /protected/account/phone/auth");
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamPhoneAct())
				.append("?token=").append(token).toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		return content;
	}

	@RequestMapping(value = "/protected/account/sms/auth", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public SMSAuthorizationResponse sendSMSAuthorizationCode(
			@RequestParam(value = "token", required = true) String token) {
		// logger.info("In /protected/account/sms/auth value of uuid:
		// "+sessionInfo().getUnAuthenticatedUUID());
		// logger.info("In /protected/account/sms/auth value of mobilenumber:
		// "+sessionInfo().getMobileNumber());
		logger.info("In /protected/account/sms/auth ");
		String sessionID = "";
		String transactionID = "";
		String userID = "";
		SecurityContextDataModel securityContextDataModel = sessionInfo().getSecurityContext();
		if (securityContextDataModel != null && securityContextDataModel.getSmsVerificationObject() != null) {
			userID = securityContextDataModel.getSmsVerificationObject().getUuid().toLowerCase();
			sessionID = securityContextDataModel.getSmsVerificationObject().getSessionId();
			transactionID = securityContextDataModel.getSmsVerificationObject().getTransactionId();

		}
		boolean ishome = false;
		if (StringUtils.containsIgnoreCase(sessionInfo().getMobileType(), "HOME")) {
			ishome = true;
		}
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamSMSAct())
				.append("?token=").append(token).append("&").append("transactionid").append("=").append(transactionID)
				.append("&").append("sessionid").append("=").append(sessionID).append("&").append("phoneno").append("=")
				.append(sessionInfo().getMobileNumber()).append("&").append("username").append("=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(userID))).append("&ishome=").append(ishome)
				.toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		// logger.info("In /protected/account/sms/auth content: "+content);
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		SMSAuthorizationResponse voiceAuthorizationResponse = null;
		try {
			voiceAuthorizationResponse = mapper.readValue(content, SMSAuthorizationResponse.class);
			if (voiceAuthorizationResponse != null && voiceAuthorizationResponse.getAuthenticationStatus() != null
					&& voiceAuthorizationResponse.getAuthenticationStatus()
							.equals(AuthenticationStatus.AUTHENTICATED)) {
				securityContextDataModel = new SecurityContextDataModel();
				securityContextDataModel.setPhoneNumberVerified(true);
				securityContextDataModel
						.setPrivilegedUserid(new String(voiceAuthorizationResponse.getUuid().toLowerCase()));
				// logger.info("In /protected/voice/challenge/status
				// smsVerficationModel.getUserId():
				// "+securityContextDataModel.getPrivilegedUserid());
				sessionInfo().setSecurityContext(securityContextDataModel);
			}
			if (voiceAuthorizationResponse != null) {
				voiceAuthorizationResponse.setUuid(null);
				voiceAuthorizationResponse.setSessionid(null);
				voiceAuthorizationResponse.setTransactionid(null);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return voiceAuthorizationResponse;
	}

	@RequestMapping(value = "/protected/account/mail/auth", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendEmailAuthorizationCode(@RequestParam(value = "token", required = true) String token) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		// RestTemplate restTemplate= new RestTemplate();
		logger.info("In /protected/account/mail/auth ");
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamEmailAct())
				.append("?token=").append(token).toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		if (StringUtils.containsIgnoreCase(content, "SUCCESS")) {
			return "{" + "\"" + "status" + "\"" + ":" + "\"" + "SUCCESS" + "\"}";
		}
		return content;
	}

	@RequestMapping(value = "/protected/admin/account/phone/verf", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String sendPhoneVerificationCode(@RequestParam(value = "phoneno", required = true) String phoneno,
			@RequestParam(value = "userid", required = true) String userid) {
		logger.info("In /protected/account/phone/verf");
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }

		// RestTemplate restTemplate= new RestTemplate();
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamPhoneVerf())
				.append("?phoneno=").append(phoneno).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).toString();

		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		logger.info("In /protected/account/phone/verf content: " + content);
		return content;
	}

	@RequestMapping(value = "/protected/account/sms/verf", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public Error sendSMSVerificationCode() {
		// logger.info("In /protected/account/sms/verf value of uuid:
		// "+sessionInfo().getUnAuthenticatedUUID());
		// logger.info("In /protected/account/sms/verf value of mobilenumber:
		// "+sessionInfo().getMobileNumber());
		// logger.info("In /protected/account/sms/verf ");
		boolean ishome = false;
		if (StringUtils.containsIgnoreCase(sessionInfo().getMobileType(), "HOME")) {
			ishome = true;
		}
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamSMSVerf())
				.append("?phoneno=").append(sessionInfo().getMobileNumber()).append("&userid=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(sessionInfo().getUnAuthenticatedUUID())))
				.append("&ishome=").append(ishome).toString();
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		// logger.info("In /protected/account/sms/verf content: "+content);

		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		SMSAuthorizationResponse smsAuthorizationResponse = null;
		// logger.info("In /protected/voice/challenge/code response: "+content);
		try {
			smsAuthorizationResponse = mapper.readValue(content, SMSAuthorizationResponse.class);
			if (smsAuthorizationResponse != null && smsAuthorizationResponse.getSessionid() != null
					&& smsAuthorizationResponse.getTransactionid() != null) {
				SecurityContextDataModel securityContextDataModel = new SecurityContextDataModel();
				SMSVerficationModel smsVerficationModel = new SMSVerficationModel();
				smsVerficationModel.setSessionId(new String(smsAuthorizationResponse.getSessionid()));
				smsVerficationModel.setTransactionId(new String(smsAuthorizationResponse.getTransactionid()));
				smsVerficationModel.setUuid(new String(sessionInfo().getUnAuthenticatedUUID().toLowerCase()));
				// logger.info("In /protected/account/sms/verf
				// smsVerficationModel.getSessionId():
				// "+smsVerficationModel.getSessionId());
				// logger.info("In /protected/account/sms/verf
				// smsVerficationModel.getTransactionId():
				// "+smsVerficationModel.getTransactionId());
				// logger.info("In /protected/account/sms/verf
				// smsVerficationModel.getUuid():
				// "+smsVerficationModel.getUuid());
				securityContextDataModel.setSmsVerificationObject(smsVerficationModel);
				sessionInfo().setSecurityContext(securityContextDataModel);

			}
			if (StringUtils.isNotBlank(smsAuthorizationResponse.getSessionid())) {
				Error error = new Error();
				error.setCode("200");
				error.setDescription("sms is sent to user");
				return error;
			} else {
				Error error = new Error();
				error.setCode("400");
				error.setDescription(smsAuthorizationResponse.getError());
				return error;
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Error error = new Error();
		error.setCode("500");
		error.setDescription("Internal Server Exception");
		return error;

	}

	private Object findSharedElement(Map<String, String> filterMap, boolean onlyEmail) throws Exception {
		return healthSafeIdService.findSharedEmailCount(filterMap, onlyEmail).get();
	}

	@RequestMapping(value = "/protected/userid/lookup", method = { RequestMethod.POST }, produces = {
			"application/json" })
	@ResponseBody
	public Map<String, String> lookupUserId(@RequestBody Map<String, String> filter,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam String captchastring,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {
		{

			if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null")) {
				lang = getLang(sessionInfo());
			}
			String captchaId = request.getSession().getId();
			logger.info("In /protected/captcha/valid/username request.getSession().getId():" + captchaId);
			Boolean isCaptchaValid = CaptchaValidator.validateCaptchaForId(captchaId, captchastring);
			// logger.info("In /protected/user/list isCaptchaValid:
			// "+isCaptchaValid);
			logger.info("In /protected/captcha/valid/username isCaptchaValid:" + isCaptchaValid);
			logger.info("In /protected/captcha/valid/username captchaAttempts.isfrgtPwdMaxLimits():"
					+ captchaAttempts.isfrgtPwdMaxLimits());
			captchaAttempts.setIsfrgtUidCaptchaPassed(isCaptchaValid);
			if (!captchaAttempts.isfrgtUidCaptchaPassed()) {
				Map<String, String> response = new HashMap<String, String>();
				response.put("code", "400");
				response.put("description", "Invalid Captcha String");
				return response;
			}
			Map<String, String> emailWrapper = new HashMap<String, String>();
			String email = filter.get("email");
			String dateOfBirth = filter.get("dateOfBirth");
			Object emailResp = null;
			// logger.info("In /protected/userid/lookup dateOfBirth:
			// "+dateOfBirth);
			// logger.info("In /protected/userid/lookup email:"+email);
			try {
				if (StringUtils.isNotBlank(email) && !EmailValidator.getInstance().isValid(email)) {
					captchaAttempts.incrFrgtUidAttempts();
					response.setStatus(HttpStatus.BAD_REQUEST.value());

				}
				if (StringUtils.isNotBlank(dateOfBirth)
						&& AuthenticationHelper.convertISOFormatToDate(dateOfBirth) == null) {
					captchaAttempts.incrFrgtUidAttempts();
					response.setStatus(HttpStatus.BAD_REQUEST.value());

				}
				Object searchWithEmailOnly = findSharedElement(filter, false);
				Object searchwithAllCerteria = findSharedElement(filter, true);

				logger.info("search with email only " + searchWithEmailOnly);
				logger.info("search with all citeria " + searchwithAllCerteria);

				if (searchWithEmailOnly instanceof Integer && searchwithAllCerteria instanceof Integer) {
					boolean sharedElement = (Integer) searchWithEmailOnly == (Integer) searchwithAllCerteria;

					emailResp = healthSafeIdService.getID(filter).get();
					if ((emailResp instanceof String) && StringUtils.isNotBlank(emailResp.toString())) {
						String portalBrand = targetPortal;
						if (sessionInfo().getInboundParameter() != null && StringUtils.isBlank(portalBrand)) {
							portalBrand = AppConstants
									.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());
						}
						logger.info("Shared element value "+sharedElement);
						if (sharedElement) {
							
							String url = new StringBuilder(ConnectionSettings.getIamServer())
									.append(ConnectionSettings.getIamForgetuserName()).append("username").append("?to=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(email)))
									.append("&username=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString((String) emailResp)))
									.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=")
									.append(targetPortal).append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL)
									.append("=").append(portalBrand).append("&")
									.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
									.append(StringUtils.isEmpty(lang) || "null".equalsIgnoreCase(lang) ? "en" : lang)
									.append("&userid=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString((String) emailResp)))
									.toString();
							// String content =
							// restTemplate.getForObject(url.trim(),String.class);
							String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
							if (StringUtils.containsIgnoreCase(content, "ERROR")) {
								captchaAttempts.incrFrgtUidAttempts();
								// logger.info("In /protected/userid/lookup
								// forgotusername:
								// Unable to send email to the user
								// "+(String)emailResp);
							}
							
							// logger.info("In /protected/userid/lookup
							// forgotusername: Sent
							// Email Successfully "+(String)emailResp);
							emailWrapper.put("code", "200");
							emailWrapper.put("description", "User found in records");
							return emailWrapper;
						} else {
							emailWrapper.put("username", (String) emailResp);
							logger.info("User found username" + emailResp);
							
							//get the respone here and send to the ui 
							emailWrapper.put("code", "204");
							emailWrapper.put("description", "User found in records");
							return emailWrapper;
						}
					}
				}

			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}
			captchaAttempts.incrFrgtUidAttempts();
			if ((emailResp instanceof com.optum.ogn.iam.model.Error)
					&& StringUtils.equalsIgnoreCase(((Error) emailResp).getCode(), "404")) {

				emailWrapper.put("code", "404");
				emailWrapper.put("description", "Multiple User Accounts Found, try by adding more filters");
				return emailWrapper;

			}
			emailWrapper.put("code", "204");
			emailWrapper.put("description", "User is not found in records");
			return emailWrapper;

		}
	}

	/*
	 * @RequestMapping(value = "/protected/admin/profile/key", method =
	 * {RequestMethod.PUT}, produces = {"application/json"})
	 * 
	 * @ResponseBody public Object resetPassword(
	 * 
	 * @RequestHeader(value= AppConstants.OPTUMID_HEADER_OPTUMID, required =
	 * true) String userId,
	 * 
	 * @RequestHeader(value= "email", required = true) String email) { // if
	 * (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) { //
	 * logger.info("incoming headers from " + request.getRequestURI() + " : " +
	 * AuthenticationHelper.getAllHeadersValue(request)); //
	 * logger.info("incoming cookies from " + request.getRequestURI() + " : " +
	 * AuthenticationHelper.getAllCookisValue(request)); // }
	 * logger.info("In /protected/admin/profile/key"); try { return
	 * healthSafeIdService.resetPassword(email, userId).get(); } catch
	 * (InterruptedException | ExecutionException e) { // TODO Auto-generated
	 * catch block e.printStackTrace(); } com.optum.ogn.iam.model.Error error =
	 * new com.optum.ogn.iam.model.Error(); error.setCode("400");
	 * error.setDescription("missing either email or sm_universalid"); return
	 * error; }
	 */

	@RequestMapping(value = "/protected/user", method = { RequestMethod.POST }, produces = { "application/json" })
	@ResponseBody
	public javax.ws.rs.core.Response registerUser(@RequestBody AddUserRequest addUserRequest) {
		// logger.info("In /protected/user: method:POST userName
		// "+addUserRequest.getUserName());
		String appAlias = null;
		if (!sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			AddUserResponse addUserResponse2 = new AddUserResponse();
			List<ErrorMessage> errorMessages = new ArrayList<ErrorMessage>();
			ErrorMessage errorMessage = new ErrorMessage();
			errorMessage.setCode("400");
			errorMessage.setDesc("Member Eligibility is failed");
			errorMessages.add(errorMessage);
			addUserResponse2.setStatus("FAILURE");
			addUserResponse2.setErrorMessages(errorMessages);
			return javax.ws.rs.core.Response.status(400).entity(addUserResponse2).build();

		}
		String phoneNo = addUserRequest.getAreaCode() + addUserRequest.getNumber();
		AddUserResponse addUserResponse = UIRequestValidator.validateUser(addUserRequest);
		if (StringUtils.equalsIgnoreCase(addUserRequest.getPhoneType(), "HOME")) {
			addUserRequest.setAreaCode(null);
			addUserRequest.setCountry(null);
			addUserRequest.setNumber(null);
		}
		if (addUserResponse == null) {

			try {
				if (sessionInfo() != null && sessionInfo().getInboundParameter() != null) {
					appAlias = "LWW";
					String targetPortal = AppConstants
							.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());

					if (StringUtils.containsIgnoreCase(targetPortal, "cap")) {

						addUserRequest.setAppAliasName("CAP");
					}
					appAlias = "CAP";

					if (StringUtils.containsIgnoreCase(targetPortal, "myuhc")
							|| StringUtils.containsIgnoreCase(targetPortal, "communityplan")
							|| StringUtils.containsIgnoreCase(targetPortal, "mymedica")
							|| StringUtils.containsIgnoreCase(targetPortal, "myhealthcareview")
							|| StringUtils.containsIgnoreCase(targetPortal, "hs")) {
						addUserRequest.setAppAliasName("myu");
						appAlias = "myu";
					}

				}
				logger.info("In /protected/user: method:POST successfully Registered into OptumId ");
				addUserResponse = healthSafeIdService.registerUser(addUserRequest).get();

				// Myuhc Changes
				if (sessionInfo().getMemberEligibility() != null
						&& sessionInfo().getMemberEligibility().getMyuhc() != null) {
					logger.info("In /protected/user: method:POST In myuhcelgibility call : eligible for myuhc");
					logger.info("In /protected/user: execute memberRegistration myuhc -before");
					MyuhcMemberRequest myuhcParameter = new MyuhcMemberRequest();
					myuhcParameter.setEligibilityKey(sessionInfo().getEligibilityKey());
					myuhcParameter.setEssoUUID(addUserResponse.getUuid());

					// update with a new variable, as
					// addUserResponse.getUserName() =first name
					myuhcParameter.setUserId(addUserRequest.getUserName());
					// myuhcParameter.setUserId(addUserResponse.getUserName());

					myuhcParameter.setEmailAddress(addUserRequest.getPrimaryEmail());
					myuhcService.getmyuhcMemberEligibility(myuhcParameter);
					logger.info("In /protected/user: execute memberRegistration call -after");
				}
				if (StringUtils.equalsIgnoreCase(addUserRequest.getPhoneType(), "HOME")) {
					Map<String, String> payLoad = new HashMap<String, String>();
					payLoad.put("phone", phoneNo);
					payLoad.put("type", "HOME");
					sessionInfo().setisMobileTypeHome(true);
					healthSafeIdService.updateUser("phone", payLoad, addUserRequest.getUserName(), null, null, false,
							getLang(sessionInfo())).get();
				}
				logger.info("In /protected/user: method:POST appAlias name is " + appAlias);
				// Myuhc Changes
				if (addUserResponse != null && addUserResponse.getUuid() != null) {
					sessionInfo().setUnAuthenticatedUUID(new String(addUserResponse.getUuid()));
					// logger.info("In /protected/user value of getUuid:
					// "+sessionInfo().getUnAuthenticatedUUID());
					sessionInfo().setUnAuthenticatedUserID(new String(addUserRequest.getUserName()));
					// logger.info("In /protected/user value of getUserId:
					// "+sessionInfo().getUnAuthenticatedUserID());
					sessionInfo().setEmail(new String(addUserRequest.getPrimaryEmail()));
					// logger.info("In /protected/user value of getEmail:
					// "+sessionInfo().getEmail());
					sessionInfo().setMobileNumber(phoneNo);
					sessionInfo().setMobileType(addUserRequest.getPhoneType());
					// logger.info("In /protected/user value of getMobileNumber:
					// "+sessionInfo().getMobileNumber());
					SecurityContextDataModel securityContext = sessionInfo().getSecurityContext();
					securityContext.setUserFromRegisteredScreen(true);
					securityContext.setPrivilegedUserid(new String(addUserResponse.getUuid()));
					sessionInfo().setSecurityContext(securityContext);
					// logger.info("In /protected/user value of
					// sessionInfo().getSecurityContext().isUserInRegistrationScreen():
					// "+sessionInfo().getSecurityContext().isUserInRegistrationScreen());
				} else {
					return javax.ws.rs.core.Response.status(400).entity(addUserResponse).build();
				}
				// logger.info("In /protected/user: method:POST userName:
				// "+addUserResponse.getUuid());
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				logger.info("In /protected/user: method:POST errror " + "Internal Server Error");
				AddUserResponse addUserResponse2 = new AddUserResponse();
				List<ErrorMessage> errorMessages = new ArrayList<ErrorMessage>();
				ErrorMessage errorMessage = new ErrorMessage();
				errorMessage.setCode("500");
				errorMessage.setDesc("Internal Server Error");
				errorMessages.add(errorMessage);
				addUserResponse2.setStatus("FAILURE");
				addUserResponse2.setErrorMessages(errorMessages);
				return javax.ws.rs.core.Response.status(500).entity(addUserResponse2).build();
			}
			addAppAccess(addUserRequest, appAlias, addUserResponse);
			javax.ws.rs.core.Response response = authenticationController
					.insertProvisioningRegistration(new String(addUserResponse.getUuid()));
			addUserResponse.setUserName(null);
			addUserResponse.setUuid(null);
			// logger.info("In /protected/user value of uuid after
			// addUserResponse.setUuid(null) :
			// "+sessionInfo().getUnAuthenticatedUUID());
			return response;
			// return addUserResponse;

		}
		return javax.ws.rs.core.Response.status(200).entity(addUserResponse).build();
	}

	public void addAppAccess(AddUserRequest addUserRequest, String appAlias, AddUserResponse addUserResponse) {
		try {
			if (StringUtils.isNotBlank(appAlias) && addUserResponse != null && addUserResponse.getUuid() != null) {
				healthSafeIdService.addAppAccess(addUserResponse.getUuid(), appAlias).get();
				String devicPrint = addUserRequest.getDevicePrint();
				String uuid = addUserResponse.getUuid();
				rememberUserDevice(devicPrint, uuid, appAlias);
			}
		} catch (InterruptedException | ExecutionException e) {
			logger.info("In /protected/user: method:POST FAILED TO ADD APPALIAS " + "Internal Server Error");
			e.printStackTrace();
		}
	}

	@RequestMapping(value = "/protected/captcha/valid/username", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public CheckUserNameResponse checkUsernameWithCaptcha(
			@RequestParam(value = "userid", required = true) String userid,
			@RequestParam(value = "captchastring", required = true) String captchastring,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String lang) {
		if (StringUtils.isEmpty(lang) || StringUtils.equalsIgnoreCase(lang, "null")) {
			lang = getLang(sessionInfo());
		}
		String captchaId = request.getSession().getId();
		Boolean isCaptchaValid = CaptchaValidator.validateCaptchaForId(captchaId, captchastring);
		// logger.info("In /protected/user/list isCaptchaValid:
		// "+isCaptchaValid);
		logger.info("In /protected/captcha/valid/username isCaptchaValid:" + isCaptchaValid);
		logger.info("In /protected/captcha/valid/username captchaAttempts.isfrgtPwdMaxLimits():"
				+ captchaAttempts.isfrgtPwdMaxLimits());
		captchaAttempts.setIsfrgtPwdCaptchaPassed(isCaptchaValid);
		if (!captchaAttempts.isfrgtPwdCaptchaPassed()) {
			CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
			checkUserNameResponse.setInfo("Invalid Captcha String");
			checkUserNameResponse.setStatus(StatusEnum.FAILURE);
			logger.info("In /protected/captcha/valid/username Invalid Captcha String");
			return checkUserNameResponse;
		}
		CheckUserNameResponse checkUserNameResponse = isUserNameValid(userid);
		logger.info("In /protected/captcha/valid/username checkUserNameResponse.getStatus():"
				+ checkUserNameResponse.getStatus().toString());
		if (checkUserNameResponse != null && checkUserNameResponse.getStatus().equals(StatusEnum.FAILURE))
			captchaAttempts.incrFrgtPwdAttempts();
		logger.info("In /protected/captcha/valid/username forgotpwd attempts:" + captchaAttempts.getFrgtPwdAttempts());
		return checkUserNameResponse;
	}

	@RequestMapping(value = "/protected/valid/username", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public CheckUserNameResponse checkUserName(@RequestParam(value = "userid", required = true) String userid) {
		if (!sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
			checkUserNameResponse.setInfo("Member Eligbility Check failed");
			checkUserNameResponse.setStatus(StatusEnum.FAILURE);
			return checkUserNameResponse;
		}
		return isUserNameValid(userid);
	}

	@RequestMapping(value = "/protected/valid/username", method = { RequestMethod.POST }, produces = {
			"application/json" })
	@ResponseBody
	public CheckUserNameResponse checkUserName(@RequestBody Map<String, String> userFilter) {
		if (!sessionInfo().getSecurityContext().isMemberEligibileDuringRegistration()) {
			CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
			checkUserNameResponse.setInfo("Member Eligbility Check failed");
			checkUserNameResponse.setStatus(StatusEnum.FAILURE);
			return checkUserNameResponse;
		}
		if (userFilter == null) {
			logger.info("In /protected/valid/username");
			CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
			checkUserNameResponse.setInfo("userid should not be null");
			checkUserNameResponse.setStatus(StatusEnum.FAILURE);
			return checkUserNameResponse;
		}
		return isUserNameValid(userFilter.get("username"));
	}

	public CheckUserNameResponse isUserNameValid(String userid) {
		logger.info("In /protected/valid/username: error " + "Internal Server Error");
		/*
		 * if(!sessionInfo().getSecurityContext().
		 * isMemberEligibileDuringRegistration()){ CheckUserNameResponse
		 * checkUserNameResponse = new CheckUserNameResponse();
		 * checkUserNameResponse.setInfo("Member Eligbility Check failed");
		 * checkUserNameResponse.setStatus(StatusEnum.FAILURE); return
		 * checkUserNameResponse; }
		 */
		if (userid == null) {
			logger.info("In /protected/valid/username");
			CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
			checkUserNameResponse.setInfo("userid should not be null");
			checkUserNameResponse.setStatus(StatusEnum.FAILURE);
			return checkUserNameResponse;
		}
		try {
			CheckUserNameResponse checkUserNameResponse = healthSafeIdService.checkUserName(userid).get();
			List<String> nameList = checkUserNameResponse.getSuggestedUsernames();
			if (nameList != null && nameList.size() > 0) {
				for (String string : nameList) {
					// logger.info("In /protected/valid/username: sujjestedName
					// "+string);
				}
			}
			return checkUserNameResponse;
		} catch (InterruptedException | ExecutionException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		logger.info("In /protected/valid/username: error " + "Internal Server Error");
		CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
		checkUserNameResponse.setInfo("Internal Server Error");
		checkUserNameResponse.setStatus(StatusEnum.FAILURE);
		return checkUserNameResponse;
	}

	@RequestMapping(value = "/protected/admin/user/lookup", method = { RequestMethod.POST }, consumes = {
			"application/json" }, produces = { "application/json" })
	@ResponseBody
	public Object searchUsers(@RequestBody Map<String, String> userFilter) {
		String email = userFilter.get("email");
		String dateOfBirth = userFilter.get("dateOfBirth");
		String firstNameString = userFilter.get("firstName");
		String lastNameString = userFilter.get("lastName");
		String phone = userFilter.get("phone");
		logger.info("In /protected/user/lookup");

		if (StringUtils.isNotBlank(email) && !EmailValidator.getInstance().isValid(email)) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());

		} else if (StringUtils.isNotBlank(dateOfBirth)
				&& AuthenticationHelper.convertISOFormatToDate(dateOfBirth) == null) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());

		}

		else {
			try {
				Map<String, String> validatedFilter = new HashMap<>();
				validatedFilter.put("email", email);
				validatedFilter.put("dateOfBirth", dateOfBirth);
				validatedFilter.put("firstName", firstNameString);
				validatedFilter.put("lastName", lastNameString);
				validatedFilter.put("phone", phone);
				return healthSafeIdService.searchUsers(validatedFilter).get();
			} catch (InterruptedException | ExecutionException e) {
				e.printStackTrace();
			}
		}

		return getGenericError();

	}

	@RequestMapping(value = "/protected/user/challenges", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public Map<String, String> getUserChanllenges() {

		try {
			logger.info("In /protected/user/challenges");
			Map<String, String> map = healthSafeIdService.getUserQuetionaire(sessionInfo().getUnAuthenticatedUserID())
					.get();
			if (map == null || map.isEmpty()) {
				map.put("code", "400");
				map.put("description", "User dont have Security Questions");
			}
			return map;
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		logger.info("In /protected/user/challenges error: " + "Internal Server Exception");
		Map<String, String> map = new HashMap<String, String>();
		map.put("code", "500");
		map.put("description", "Internal Server Exception");
		return map;
	}

	@RequestMapping(value = "/protected/user/challenges", method = { RequestMethod.POST }, produces = {
			"application/json" })
	@ResponseBody
	public Map<String, String> getUserChanllenges(@RequestBody Map<String, String> payLoad) {
		try {
			logger.info("In /protected/user/challenges");
			Map<String, String> map = healthSafeIdService
					.validateUserQuestionaire(payLoad, sessionInfo().getUnAuthenticatedUserID()).get();
			if (map != null && map.size() > 0) {
				if (StringUtils.equalsIgnoreCase(map.get("description"), "User Security Answers are Correct")) {
					SecurityContextDataModel securityContextDataModel = new SecurityContextDataModel();
					securityContextDataModel.setSecurityQuestionsValidated(true);
					securityContextDataModel.setPrivilegedUserid(sessionInfo().getUnAuthenticatedUserID());
					// logger.info("In /protected/user/challenges
					// securityContextDataModel.setSecurityQuestionsValidated:
					// "+securityContextDataModel.isSecurityQuestionsValidated());
					// logger.info("In /protected/user/challenges
					// securityContextDataModel.getUserID:
					// "+securityContextDataModel.getPrivilegedUserid());
					securityContextDataModel.setUserFromRegisteredScreen(
							sessionInfo().getSecurityContext().isUserInRegistrationScreen());
					securityContextDataModel.setMemberEligibileDuringRegistration(
							sessionInfo().getSecurityContext().isUserInRegistrationScreen());
					sessionInfo().setSecurityContext(securityContextDataModel);
				}
			}
			return map;
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		logger.info("In /protected/user/challenges method:POST error: " + "Internal Server Exception");
		Map<String, String> error = new HashMap<String, String>();
		error.put("code", "500");
		error.put("description", "Internal Server Exception");
		return error;
	}

	public static String getGenericError() {
		Response response2 = new Response();
		response2.setStatus(com.optum.ogn.iam.model.Response.StatusEnum.FAILURE);
		com.optum.ogn.iam.model.Errors errors = new com.optum.ogn.iam.model.Errors();
		List<com.optum.ogn.iam.model.Error> errorList = new ArrayList<com.optum.ogn.iam.model.Error>();
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("500");
		error.setDescription("Internal Server Exception");
		errorList.add(error);
		response2.setErrors(errors);
		errors.setError(errorList);
		response2.setErrors(errors);
		ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(Include.NON_NULL);
		try {
			return mapper.writeValueAsString(response2);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	@RequestMapping(value = "/protected/admin/account/email/verf/token", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public String getEmailVerfToken(@RequestParam(value = "to", required = true) String email,
			@RequestParam(value = "userid", required = true) String userid) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }

		// RestTemplate restTemplate= new RestTemplate();
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(ConnectionSettings.getIamEmailVerf())
				.append("/token").append("?to=").append(java.net.URLEncoder.encode(StringUtils.defaultString(email)))
				.append("&userid=").append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).toString();
		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		// logger.info("In /protected/account/email/verf/token content:
		// "+content);
		return content;
	}

	@RequestMapping(value = "/protected/voice/challenge/code", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public VoiceAuthorizationResponse getVoiceChallenge() {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		// RestTemplate restTemplate= new RestTemplate();
		// logger.info("In /protected/voice/challenge/code value of
		// sessionInfo().getUuid(): "+sessionInfo().getUnAuthenticatedUUID());
		// logger.info("In /protected/voice/challenge/code value of
		// sessionInfo().getMobileNumber(): "+sessionInfo().getMobileNumber());
		boolean ishome = false;
		if (StringUtils.containsIgnoreCase(sessionInfo().getMobileType(), "HOME")) {
			ishome = true;
		}
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(voiceCallChallenge).append("?phone=")
				.append(sessionInfo().getMobileNumber()).append("&username=")
				.append(java.net.URLEncoder.encode(StringUtils.defaultString(sessionInfo().getUnAuthenticatedUUID())))
				.append("&ishome=").append(ishome).toString();

		// String content = restTemplate.getForObject(url.trim(),String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		VoiceAuthorizationResponse voiceAuthorizationResponse = null;
		// logger.info("In /protected/voice/challenge/code response: "+content);
		try {
			voiceAuthorizationResponse = mapper.readValue(content, VoiceAuthorizationResponse.class);
			if (voiceAuthorizationResponse != null) {
				SecurityContextDataModel securityContextDataModel = new SecurityContextDataModel();
				SMSVerficationModel smsVerficationModel = new SMSVerficationModel();
				smsVerficationModel.setSessionId(new String(voiceAuthorizationResponse.getSessionid()));
				smsVerficationModel.setTransactionId(new String(voiceAuthorizationResponse.getTransactionid()));
				smsVerficationModel.setUuid(new String(sessionInfo().getUnAuthenticatedUUID().toLowerCase()));
				// logger.info("In /protected/voice/challenge/code
				// smsVerficationModel.getSessionId():
				// "+smsVerficationModel.getSessionId());
				// logger.info("In /protected/voice/challenge/code
				// smsVerficationModel.getTransactionId():
				// "+smsVerficationModel.getTransactionId());
				// logger.info("In /protected/voice/challenge/code
				// smsVerficationModel.getUuid():
				// "+smsVerficationModel.getUuid());
				securityContextDataModel.setSmsVerificationObject(smsVerficationModel);
				securityContextDataModel
						.setUserFromRegisteredScreen(sessionInfo().getSecurityContext().isUserInRegistrationScreen());
				securityContextDataModel.setMemberEligibileDuringRegistration(
						sessionInfo().getSecurityContext().isUserInRegistrationScreen());
				if (sessionInfo().getSecurityContext() != null
						&& sessionInfo().getSecurityContext().getPrivilegedUserid() != null)
					securityContextDataModel
							.setPrivilegedUserid(new String(sessionInfo().getSecurityContext().getPrivilegedUserid()));
				sessionInfo().setSecurityContext(securityContextDataModel);
				voiceAuthorizationResponse.setUuid(null);
				voiceAuthorizationResponse.setSessionid(null);
				voiceAuthorizationResponse.setTransactionid(null);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return voiceAuthorizationResponse;
	}

	@RequestMapping(value = "/protected/voice/challenge/status", method = { RequestMethod.GET }, produces = {
			"application/json" })
	@ResponseBody
	public VoiceAuthorizationResponse getVoiceStatus() {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		String sessionID = "";
		String transactionID = "";
		String userID = "";
		String phone = "";
		SecurityContextDataModel securityContextDataModel = sessionInfo().getSecurityContext();
		if (securityContextDataModel != null && securityContextDataModel.getSmsVerificationObject() != null) {
			userID = securityContextDataModel.getSmsVerificationObject().getUuid().toLowerCase();
			sessionID = securityContextDataModel.getSmsVerificationObject().getSessionId();
			transactionID = securityContextDataModel.getSmsVerificationObject().getTransactionId();

		}
		boolean ishome = false;
		if (StringUtils.containsIgnoreCase(sessionInfo().getMobileType(), "HOME")) {
			ishome = true;
			try {
				phone = healthSafeIdService.getProfileInfo(userID, "HOME").get().get("phone");
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else {
			try {
				phone = healthSafeIdService.getProfileInfo(userID, "MOBILE").get().get("phone");
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

		// RestTemplate restTemplate= new RestTemplate();
		String url = new StringBuilder(ConnectionSettings.getIamServer()).append(voiceCallStatus)
				.append("?transactionid=").append(transactionID).append("&sessionid=").append(sessionID)
				.append("&username=").append(java.net.URLEncoder.encode(StringUtils.defaultString(userID)))
				.append("&phone=").append(phone).append("&ishome=").append(ishome).toString();
		// String content = restTemplate.getForObject(url.trim(), String.class);
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		// logger.info("In /protected/voice/challenge/status response:
		// "+content);
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		VoiceAuthorizationResponse voiceAuthorizationResponse = null;
		try {
			voiceAuthorizationResponse = mapper.readValue(content, VoiceAuthorizationResponse.class);
			if (voiceAuthorizationResponse != null && voiceAuthorizationResponse.getAuthenticationStatus() != null
					&& voiceAuthorizationResponse.getAuthenticationStatus()
							.equals(AuthenticationStatus.AUTHENTICATED)) {
				securityContextDataModel = new SecurityContextDataModel();
				securityContextDataModel.setPhoneNumberVerified(true);
				securityContextDataModel
						.setPrivilegedUserid(new String(voiceAuthorizationResponse.getUuid().toLowerCase()));
				// logger.info("In /protected/voice/challenge/status
				// smsVerficationModel.getUserId():
				// "+securityContextDataModel.getPrivilegedUserid());
				sessionInfo().setSecurityContext(securityContextDataModel);
			}
			if (voiceAuthorizationResponse != null) {
				voiceAuthorizationResponse.setUuid(null);
				voiceAuthorizationResponse.setSessionid(null);
				voiceAuthorizationResponse.setTransactionid(null);
				voiceAuthorizationResponse.setToken(null);
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return voiceAuthorizationResponse;
	}

	/*******************************************************************************************************************
	 * End of Services Endpoint
	 *******************************************************************************************************************/

	/*******************************************************************************************************************
	 * Start of View
	 *******************************************************************************************************************/

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public ModelAndView login() {

		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }
		logger.info("In /login method:GET ");
		ModelAndView mv = new ModelAndView("healthsafeid/error-login");

		Map<String, String[]> paramenterMap = request.getParameterMap();

		// if (paramenterMap.containsKey("TARGET") && paramenterMap.size() > 1)
		// {
		//
		// String target = request.getParameter("TARGET");
		// StringBuilder targetUrl = new
		// StringBuilder("login?TARGET=").append(URLEncoder.encode(target));
		// RedirectView v = new RedirectView(targetUrl.toString());
		// v.setHttp10Compatible(false);
		// return new ModelAndView(v);
		//
		// } else {

		String target = request.getParameter("TARGET");
		String userInput = "";
		boolean smTried = false;

		if (StringUtils.isNotBlank(StringUtils.trim(loginAttempt.getCurrentInput()))) {
			userInput = StringUtils.trim(loginAttempt.getCurrentInput());
		}

		if (StringUtils.isNotBlank(target)) {
			target = target.replace("$SM$", "");
		}
		String targetUrl = "";
		try {

			URL originTarget = new URL(target);

			if (!StringUtils.startsWithIgnoreCase(originTarget.getPath(), "/secure/authenticate") && !StringUtils
					.startsWithIgnoreCase(originTarget.getHost(), new URL(request.getServerName()).getHost())) {
				target = new StringBuilder(request.getServerName()).append("/secure/authenticate?")
						.append(AppConstants.OPTUMID_HEADER_TARGETURL).append("=").append(originTarget).append("&")
						.append(StringUtils.substring(originTarget.getQuery(), 1)).toString();
			}

			target = setupDefault(target);

			String targetPortal = PortalDestinationType
					.fromValue(extractRequestValue(target, AppConstants.OPTUMID_HEADER_TARGETPORTAL + "=", "&")).name();

			targetUrl = extractRequestValue(target, AppConstants.OPTUMID_HEADER_TARGETURL + "=", "&");
			String errorUrl = extractRequestValue(target, AppConstants.OPTUMID_HEADER_ERRORURL + "=", "&");
			String accessCode = extractRequestValue(target, AppConstants.OPTUMID_HEADER_ACCESSCODE + "=", "&");
			String accessType = extractRequestValue(target, AppConstants.OPTUMID_HEADER_ACCESSTYPE + "=", "&");
			String brandUrl = extractRequestValue(target, AppConstants.OPTUMID_HEADER_BRANDURL + "=", "&");
			String eligibility = extractRequestValue(target, AppConstants.OPTUMID_HEADER_ELIGIBILITY + "=", "&");
			String language = extractRequestValue(target, AppConstants.OPTUMID_HEADER_LANGUAGE + "=", "&");
			String isConfirmLink = "";
			if (sessionInfo().getInboundParameter() != null) {
				isConfirmLink = sessionInfo().getInboundParameter().getIsConfirmLink();
			}

			if (!StringUtils.equalsIgnoreCase("true", isConfirmLink))
				authenticationController.setupInbound(AppConstants.ACTION.valueOf(AppConstants.ACTION.SIGNIN.name()),
						null, null, accessCode, accessType, null, null, null, null, errorUrl, null, null, null, null,
						null, null, null, null, null, null, targetPortal, targetUrl, null, null, null, brandUrl, null,
						eligibility, language, null);

			if (!isTargetUrlValid(AppConstants.ACTION.SIGNIN, PortalDestinationType.fromValue(targetPortal),
					targetUrl)) {
				response.setStatus(HttpStatus.BAD_REQUEST.value());
				return validationController.renderGeneralError();
			}

			if (StringUtils.contains(target, AppConstants.OPTUMID_HEADER_TARGETPORTAL)
					&& StringUtils.contains(target, AppConstants.OPTUMID_HEADER_TARGETURL)) {

				if (StringUtils.isNotBlank(userInput)) {
					smTried = true;
				}

				mv = new ModelAndView("healthsafeid/login");
				mv.addObject("smTried", smTried);
				mv.addObject("userInput", userInput);
				mv.addObject("target", target);
				mv.addObject("targetPortal", targetPortal);
				mv.addObject("globalnav", externalIntegrationConfiguration.getGlobalnav());

			}

		} catch (Exception e) {
			e.printStackTrace();
			// logger.info("Malformed Origin Target at /login: " +
			// request.getParameter("TARGET"));
			// logger.info("Malformed Built Target at /login: " + target);
		}
		String targetPortal = AppConstants.getPortalBrand(sessionInfo().getInboundParameter().getTargetUrl());
		String appAlias = "";
		if (StringUtils.containsIgnoreCase(targetPortal, "myuhc")
				|| StringUtils.containsIgnoreCase(targetPortal, "communityplan")
				|| StringUtils.containsIgnoreCase(targetPortal, "mymedica")
				|| StringUtils.containsIgnoreCase(targetPortal, "myhealthcareview")
				|| StringUtils.containsIgnoreCase(targetPortal, "hs")) {
			appAlias = "myu";
		}
		if (sessionInfo() != null && sessionInfo().getInboundParameter() != null
				&& sessionInfo().getInboundParameter().getResetURL() != null)
			setDeviceCookie("hsid_resetpwdurl", sessionInfo().getInboundParameter().getResetURL(), request, response,
					appAlias);
		return mv;

		// }

	}

	@RequestMapping(value = "/content/en/healthsafeid/public/logout.html", method = { RequestMethod.GET })
	public ModelAndView logout(@RequestParam(value = "keep", required = false) boolean keep) {
		if (!keep)
			httpSession.invalidate();

		ModelAndView mv = new ModelAndView("healthsafeid/logout");
		return mv;
	}

	private String extractRequestValue(String url, String preffix, String suffix) {
		String value = StringUtils.substringAfter(url, preffix);
		value = StringUtils.substringBefore(value, suffix);

		return value;
	}

	/*
	 * Default for portals that don't provide one or more of the following
	 * attribute HTTP_TARGETURL HTTP_ERRORURL HTTP_TARGETPORTAL HTTP_ACCESSTYPE
	 * The default values are determined by the domain name. Ref
	 * PortalSettingUtil.getPortalDefault()
	 */
	private String setupDefault(String targetURL) throws URISyntaxException {
		// logger.info("TargetURL(Original): "+targetURL);
		String targetPortalURL = StringUtils.substringAfter(targetURL, AppConstants.OPTUMID_HEADER_TARGETURL + "=");
		if (targetPortalURL == null || targetPortalURL.trim().length() == 0) {
			targetPortalURL = StringUtils.substringAfter(targetURL, "TARGET=");
			targetPortalURL = StringUtils.replace(targetPortalURL, "$", "");
		}

		// Mobile App will not use http for targetPortalUrl
		if (StringUtils.startsWithIgnoreCase(targetPortalURL, "http")) {

			List<PortalSetting> portalSettingList = SiteminderPortalDefaultSettingUtil.getPortalDefaultByDomainName();
			String domain = URLHelper.getDomainName(targetPortalURL);
			String path = URLHelper.getPath(targetPortalURL);
			path = StringUtils.substringBefore(path, "&");
			// logger.info("Path: "+path);
			PortalSetting portalSetting = null;
			if (domain.equalsIgnoreCase("myoptum-dev.optum.com") || domain.equalsIgnoreCase("myoptum-test.optum.com")
					|| domain.equalsIgnoreCase("myoptum-demo.optum.com")
					|| domain.equalsIgnoreCase("myoptum-stage.optum.com")) {
				portalSetting = SiteminderPortalDefaultSettingUtil.searchPortal(portalSettingList, domain, path);
			} else {
				portalSetting = SiteminderPortalDefaultSettingUtil.searchPortal(portalSettingList, domain);
			}

			if (!StringUtils.contains(targetURL, AppConstants.OPTUMID_HEADER_ERRORURL) && portalSetting != null) {
				targetURL += "&" + AppConstants.OPTUMID_HEADER_ERRORURL + "=" + portalSetting.getPortalErrorUrl();
			}
			if (!StringUtils.contains(targetURL, AppConstants.OPTUMID_HEADER_TARGETURL) && portalSetting != null) {
				String targeturl = portalSetting.getPortalTargetUrl();
				if (StringUtils.contains(targeturl, "{TARGET}")) {
					targeturl = StringUtils.replace(targeturl, "{TARGET}", targetPortalURL);
				}
				if (StringUtils.contains(targeturl, "{TARGET.PATH}")) {
					targeturl = StringUtils.replace(targeturl, "{TARGET.PATH}", URLHelper.getPath(targetPortalURL));
				}
				if (StringUtils.contains(targeturl, "{TARGET.PATH.QUERY}")) {
					targeturl = StringUtils.replace(targeturl, "{TARGET.PATH.QUERY}",
							URLHelper.getQuery(targetPortalURL));
				}
				targetURL += "&" + AppConstants.OPTUMID_HEADER_TARGETURL + "=" + targeturl;
			}
			if (!StringUtils.contains(targetURL, AppConstants.OPTUMID_HEADER_ACCESSTYPE) && portalSetting != null
					&& portalSetting.getPortalAccessType() != null) {
				targetURL += "&" + AppConstants.OPTUMID_HEADER_ACCESSTYPE + "=" + portalSetting.getPortalAccessType();
			}
			if (!StringUtils.contains(targetURL, AppConstants.OPTUMID_HEADER_TARGETPORTAL) && portalSetting != null) {
				targetURL += "&" + AppConstants.OPTUMID_HEADER_TARGETPORTAL + "=" + portalSetting.getPortalType();
			} else if (StringUtils.contains(targetURL, AppConstants.OPTUMID_HEADER_TARGETPORTAL)
					&& portalSetting != null) {
				if (StringUtils.contains(targetURL, "DASHBOARD")
						&& portalSetting.getPortalType().equalsIgnoreCase("CCD")) {
					targetURL = StringUtils.replace(targetURL, "DASHBOARD", "CCD");
				} else if (StringUtils.contains(targetURL, "ccd")
						&& portalSetting.getPortalType().equalsIgnoreCase("CCD")) {
					targetURL = StringUtils.replace(targetURL, "ccd", "CCD");
				}
			}
		}
		// logger.info("TargetURL(Transformed): "+targetURL);
		return targetURL;
	}

	// @RequestMapping(value = "/login", method = {RequestMethod.POST})
	// public ModelAndView handleSMLogin(@RequestParam(value= "user", required =
	// true) String userOrEmail,
	// @RequestParam(value= "password", required = true) String password,
	// @RequestParam(value= "target", required = true) String target,
	// @RequestParam(value= "method", required = true) String method
	// ) {
	// logger.info("In /login method:POST");
	// ModelAndView mv = new ModelAndView("healthsafeid-signin-proxy");
	// mv.addObject("target", target);
	// mv.addObject("method", method);
	// mv.addObject("password", password);
	// mv.addObject("email", userOrEmail);
	//
	// Map<String, String> userLookup = new HashedMap();
	// userLookup.put("email", userOrEmail);
	// Map<String, String> userResp = lookupUserIdByEmail(userLookup);
	// String userId = userResp.get("userId");
	// mv.addObject("userid", userId);
	//
	// return mv;
	// }

	@RequestMapping(value = "/protected/accountreset/{part}")
	public ModelAndView accountReset(@PathVariable String part,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = true) String targetUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ELIGIBILITY, required = false) String eligibility,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String language,

			Map<String, Object> model) {

		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// }
		if (StringUtils.isEmpty(language) || StringUtils.equalsIgnoreCase(language, "null")) {
			language = getLang(sessionInfo());
		}
		httpSession.invalidate();

		authenticationController.setupInbound(AppConstants.ACTION.valueOf(part.toUpperCase()), null, null, accessCode,
				accessType, null, null, null, null, errorUrl, null, null, null, null, null, null, null, null, null,
				null, targetPortal, targetUrl, null, null, null, brandUrl, null, eligibility, language, null);
		if (part.equalsIgnoreCase("password")) {
			ModelAndView mv = new ModelAndView("healthsafeid/reset-password");
			mv.addObject("globalnav", externalIntegrationConfiguration.getGlobalnav());
			mv.addObject("targetPortal", targetPortal);
			return mv;
		}
		ModelAndView mv2 = new ModelAndView("healthsafeid/reset-account");
		mv2.addObject("targetPortal", targetPortal);
		mv2.addObject("globalnav", externalIntegrationConfiguration.getGlobalnav());
		return mv2;

	}

	@RequestMapping(value = "/secure/settings")
	public ModelAndView accountSettings(
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = true) String targetUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_SIGNOUTURL, required = false) String signOutUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TIMEOUTURL, required = false) String timeOutUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_DESTINATIONURL, required = false) String destinationUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_DESTINATIONSITEURL, required = false) String destinationSiteminderUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_HSIDSITEURL, required = false) String healthsafeIdSiteminderUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String language,
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_UUID, required = true) String uuid) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// }
		if (StringUtils.isEmpty(language) || StringUtils.equalsIgnoreCase(language, "null")) {
			language = getLang(sessionInfo());
		}
		httpSession.invalidate();

		authenticationController.setupInbound(AppConstants.ACTION.valueOf(AppConstants.ACTION.SIGNIN.name()), null,
				null, accessCode, accessType, null, null, null, null, errorUrl, null, null, null, null, null, null,
				null, null, null, null, targetPortal, targetUrl, uuid, null, null, brandUrl, null, null, language,
				null);
		sessionInfo().setSignOutUrl(signOutUrl);
		sessionInfo().setTimeOutUrl(timeOutUrl);
		sessionInfo().setDestinationUrl(destinationUrl);
		sessionInfo().setDestinationSiteminderUrl(destinationSiteminderUrl);
		sessionInfo().setHealthsafeIdSiteminderUrl(healthsafeIdSiteminderUrl);
		sessionInfo().getSecurityContext().setMemberEligibileDuringRegistration(true);
		ModelAndView mv2 = new ModelAndView("healthsafeid/accountSettings");
		mv2.addObject("globalnav", externalIntegrationConfiguration.getGlobalnav());
		mv2.addObject("targetPortal", targetPortal);
		return mv2;
	}

	@RequestMapping(value = "/protected/account/confirmemail", method = { RequestMethod.GET }, produces = {
			"application/json" })
	public ModelAndView activateMail(@RequestParam(value = "token", required = true) String token,
			@RequestParam(value = "source", required = true) String source,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSCODE, required = false) String accessCode,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ACCESSTYPE, required = false) String accessType,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ERRORURL, required = false) String errorUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETPORTAL, required = true) String targetPortal,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_TARGETURL, required = true) String targetUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_BRANDURL, required = false) String brandUrl,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_ELIGIBILITY, required = false) String eligibility,
			@RequestParam(value = AppConstants.OPTUMID_HEADER_LANGUAGE, required = false) String language) {
		// if
		// (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
		// logger.info("incoming headers from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllHeadersValue(request));
		// logger.info("incoming cookies from " + request.getRequestURI() + " :
		// " + AuthenticationHelper.getAllCookisValue(request));
		// }

		if (StringUtils.isEmpty(language) || StringUtils.equalsIgnoreCase(language, "null")) {
			language = getLang(sessionInfo());
		}

		httpSession.invalidate();
		authenticationController.setupInbound(AppConstants.ACTION.valueOf(AppConstants.ACTION.SIGNIN.name()), null,
				null, accessCode, accessType, null, null, null, null, errorUrl, null, null, null, null, null, null,
				null, null, null, null, targetPortal, targetUrl, null, null, null, brandUrl, null, eligibility,
				language, null);
		sessionInfo().getInboundParameter().setIsConfirmLink("true");
		sessionInfo().getInboundParameter().setIsConfirmCodeValidated("false");
		if (StringUtils.equalsIgnoreCase(source, "registration")) {
			sessionInfo().getInboundParameter().setIsFromRegistation("true");
			sessionInfo().getInboundParameter().setIsFromProfileUpdate("false");
		} else {
			sessionInfo().getInboundParameter().setIsFromRegistation("false");
			sessionInfo().getInboundParameter().setIsFromProfileUpdate("true");
		}

		ModelAndView modelAndView = AuthenticationHelper
				.redirectTargetURL(sessionInfo().getInboundParameter().getSigninURL());
		targetUrl = StringUtils.removeEnd(targetUrl, "/");
		if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "communityplan")) {

			if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "communityplan"), "?")) {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "communityplan") + "&emailConfirmStatus=false");
			} else {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "communityplan") + "?emailConfirmStatus=false");
			}

		} else if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "myhealthcareview")) {
			if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "myhealthcareview"), "?")) {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "myhealthcareview") + "&emailConfirmStatus=false");
			} else {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "myhealthcareview") + "?emailConfirmStatus=false");
			}

		} else if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "myuhc")) {
			if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "myuhc"), "?")) {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "myuhc") + "&emailConfirmStatus=false");
			} else {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "myuhc") + "?emailConfirmStatus=false");
			}

		} else if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "hs")
				&& StringUtils.containsIgnoreCase(targetPortal, "myuhc")) {
			if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "hs"), "?")) {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "hs") + "&emailConfirmStatus=false");
			} else {
				modelAndView = AuthenticationHelper.redirectTargetURL(
						contentController.getSignInUrl(language, "hs") + "?emailConfirmStatus=false");
			}

		} else if (StringUtils.isNotBlank(targetPortal) && StringUtils.containsIgnoreCase(targetPortal, "gehub")) {
			modelAndView = AuthenticationHelper.redirectTargetURL(targetUrl);
		}

		// RedirectView mv = new
		// RedirectView(sessionInfo().getInboundParameter().getSigninURL());
		// ModelAndView modelAndView = new ModelAndView(mv);
		// RestTemplate restTemplate= new RestTemplate();
		String url = new StringBuilder(ConnectionSettings.getIamServer())
				.append(ConnectionSettings.getIamConfirmEmail()).append("?token=").append(token).toString();
		String content = ConnectionSettings.getRestClient(url.trim()).getAsJson(String.class);
		// String content = restTemplate.getForObject(url.trim(),String.class);
		if (StringUtils.contains(content, "SUCCESS")) {
			sessionInfo().getInboundParameter().setIsConfirmCodeValidated("true");
			if (StringUtils.isNotBlank(targetPortal) && StringUtils.containsIgnoreCase(targetPortal, "gehub")) {
				modelAndView = AuthenticationHelper.redirectTargetURL(targetUrl);
			} else if (StringUtils.isNotBlank(targetUrl)
					&& StringUtils.containsIgnoreCase(targetUrl, "communityplan")) {

				if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "communityplan"), "?")) {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "communityplan") + "&emailConfirmStatus=true");
				} else {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "communityplan") + "?emailConfirmStatus=true");
				}

			} else if (StringUtils.isNotBlank(targetUrl)
					&& StringUtils.containsIgnoreCase(targetUrl, "myhealthcareview")) {
				if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "myhealthcareview"), "?")) {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "myhealthcareview") + "&emailConfirmStatus=true");
				} else {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "myhealthcareview") + "?emailConfirmStatus=true");
				}

			} else if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "myuhc")) {
				if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "myuhc"), "?")) {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "myuhc") + "&emailConfirmStatus=true");
				} else {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "myuhc") + "?emailConfirmStatus=true");
				}

			} else if (StringUtils.isNotBlank(targetUrl) && StringUtils.containsIgnoreCase(targetUrl, "hs")
					&& StringUtils.containsIgnoreCase(targetPortal, "myuhc")) {
				if (StringUtils.containsIgnoreCase(contentController.getSignInUrl(language, "hs"), "?")) {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "hs") + "&emailConfirmStatus=true");
				} else {
					modelAndView = AuthenticationHelper.redirectTargetURL(
							contentController.getSignInUrl(language, "hs") + "?emailConfirmStatus=true");
				}
			}

			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			Response user;
			String email = null;
			String userid = null;
			String username = null;
			try {
				user = mapper.readValue(content, Response.class);
				if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
						&& user.getInfo() == null) {
					Resource resource = user.getResource();
					if (resource != null) {
						IdentificationData identificationData = resource.getUserIdentificationData();
						if (identificationData != null) {
							username = identificationData.getUserName().getValue();
							modelAndView.addObject("userid", identificationData.getUserName().getValue());
							modelAndView.addObject("UUID", identificationData.getUUID().getValue());
							sessionInfo().getInboundParameter().setUuid(identificationData.getUUID().getValue());
							// logger.info("In /protected/account/confirmemail
							// userid=
							// "+identificationData.getUserName().getValue());
						}
						UserPayload userPayload = resource.getUserPayload();
						if (userPayload != null) {
							List<EmailAddress> emailList = userPayload.getEmails();
							if (emailList != null && emailList.size() > 0) {
								for (EmailAddress emailAddress : emailList) {
									if (StringUtils.equalsIgnoreCase("Primary", emailAddress.getLabel()))
										email = emailAddress.getValue();
									modelAndView.addObject("email", email);
									// logger.info("In
									// /protected/account/confirmemail email=
									// "+email);
									sessionInfo().getInboundParameter().setEmail(email);

								}
							}
							UserDetail userDetail = userPayload.getUserDetail();
							if (userDetail != null) {

								List<PhoneNumber> phoneNumbers = userDetail.getPhoneNumbers();
								if (phoneNumbers != null) {
									for (PhoneNumber phoneNumber : phoneNumbers) {
										sessionInfo().getInboundParameter()
												.setPhone(phoneNumber.getAreaCode() + phoneNumber.getNumber());
									}
								}
							}
						}
					}
					// RestTemplate restT= new RestTemplate();
					String confirmUrl = null;
					if (StringUtils.equalsIgnoreCase(source, "registration")) {
						confirmUrl = new StringBuilder(ConnectionSettings.getIamServer())
								.append(ConnectionSettings.getIamEmailVerf()).append("/regist").append("?to=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(email)))
								.append("&username=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(username))).append("&")
								.append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
								.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
								.append(AppConstants.getPortalBrand(targetUrl)).append("&")
								.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
								.append(StringUtils.isEmpty(language) || "null".equalsIgnoreCase(language) ? "en"
										: language)
								.append("&userid=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).toString();
						sessionInfo().getInboundParameter().setIsFromRegistation("true");
						sessionInfo().getInboundParameter().setIsFromProfileUpdate("false");
					} else if (StringUtils.equalsIgnoreCase(source, "profileUpdate")) {
						confirmUrl = new StringBuilder(ConnectionSettings.getIamServer())
								.append(ConnectionSettings.getIamForgetuserName()).append("newmail").append("?to=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(email)))
								.append("&username=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(username))).append("&")
								.append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
								.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
								.append(AppConstants.getPortalBrand(targetUrl)).append("&")
								.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
								.append(StringUtils.isEmpty(language) || "null".equalsIgnoreCase(language) ? "en"
										: language)
								.append("&userid=")
								.append(java.net.URLEncoder.encode(StringUtils.defaultString(userid))).toString();
						sessionInfo().getInboundParameter().setIsFromProfileUpdate("true");
						sessionInfo().getInboundParameter().setIsFromRegistation("false");
					}
					if (StringUtils.isNotBlank(confirmUrl))
						// restT.getForObject(confirmUrl.trim(),String.class);
						ConnectionSettings.getRestClient(confirmUrl.trim()).getAsJson(String.class);

				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		modelAndView.addObject("killSM", true);
		modelAndView.addObject("killSMURL", "/content/en/healthsafeid/public/logout.html?keep=true");
		return modelAndView;
	}

	/*
	 * @RequestMapping(value = "/secure/audit", method = {RequestMethod.POST},
	 * produces = {"application/json"})
	 * 
	 * @ResponseBody public Object auditUserActivity( @RequestBody UserAudit
	 * userAudit, @RequestHeader(value= AppConstants.OPTUMID_HEADER_OPTUMID,
	 * required = true) String userId) { // if
	 * (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) { //
	 * logger.info("incoming headers from " + request.getRequestURI() + " : " +
	 * AuthenticationHelper.getAllHeadersValue(request)); //
	 * logger.info("incoming cookies from " + request.getRequestURI() + " : " +
	 * AuthenticationHelper.getAllCookisValue(request)); // }
	 * 
	 * try { if(StringUtils.isNotBlank(userAudit.getSessionID()) &&
	 * StringUtils.isNotBlank(userAudit.getActivity())
	 * &&StringUtils.isNotBlank(userAudit.getClientIPAddr())
	 * &&StringUtils.isNotBlank(userAudit.getSourceIPAddr())
	 * &&StringUtils.isNotBlank(userAudit.getMessage())
	 * &&StringUtils.isNotBlank(userAudit.getUserId())
	 * &&StringUtils.isNotBlank(userAudit.getLogLevel())){ Object resp =
	 * healthSafeIdService.auditUser(userAudit).get(); return resp; }
	 * 
	 * } catch (InterruptedException | ExecutionException e) { // TODO
	 * Auto-generated catch block e.printStackTrace(); }
	 * 
	 * ErrorMessage errorMessage = new ErrorMessage();
	 * errorMessage.setCode("500");
	 * errorMessage.setDesc("Internal Server Error"); return errorMessage; }
	 */

	/*
	 * @RequestMapping(value = "/secure/access/app", method =
	 * {RequestMethod.POST}, produces = {"application/json"})
	 * 
	 * @ResponseBody public Object addAppaccess( @RequestHeader(value=
	 * "rpalias", required = true) String rpalias, @RequestHeader(value= "uuid",
	 * required = true) String uuid, @RequestHeader(value=
	 * AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String userId) { //
	 * if (ConnectionSettings.securityTestHarness().equalsIgnoreCase("true")) {
	 * // logger.info("incoming headers from " + request.getRequestURI() + " : "
	 * + AuthenticationHelper.getAllHeadersValue(request)); //
	 * logger.info("incoming cookies from " + request.getRequestURI() + " : " +
	 * AuthenticationHelper.getAllCookisValue(request)); // } Object resp; try {
	 * resp = healthSafeIdService.addAppAccess(uuid,rpalias).get();
	 * logger.info("In /secure/access/app successful response "); return resp; }
	 * catch (InterruptedException | ExecutionException e) { // TODO
	 * Auto-generated catch block e.printStackTrace(); }
	 * 
	 * ErrorMessage errorMessage = new ErrorMessage();
	 * errorMessage.setCode("500");
	 * errorMessage.setDesc("Internal Server Error"); return errorMessage; }
	 */

	@RequestMapping(value = "/secure/user/phone", method = { RequestMethod.PUT }, produces = { "application/json" })
	@ResponseBody
	public Object deleteUserPhone(
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String optumId,
			@RequestParam(value = "del", required = true) String delete) {
		if (StringUtils.isNotBlank(optumId) && StringUtils.equalsIgnoreCase(delete, "true")) {
			try {
				return healthSafeIdService.deleteUserPhone(optumId).get();
			} catch (InterruptedException | ExecutionException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
			error.setCode("500");
			error.setDescription("Internal Server Exception");
			return error;
		}
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("400");
		error.setDescription("Bad request");
		return error;
	}

	@RequestMapping(value = "/secure/user/list", method = { RequestMethod.GET }, produces = { "application/json" })
	@ResponseBody
	public Response getSecureUserInfo(
			@RequestHeader(value = AppConstants.OPTUMID_HEADER_OPTUMID, required = true) String optumId) {
		logger.info("In /secure/user/list");
		String responseString = null;
		Response oResponse = null;
		try {
			responseString = healthSafeIdService.getSecureUserList(optumId).get();
			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			oResponse = mapper.readValue(responseString, Response.class);
			if (oResponse != null && StringUtils.equalsIgnoreCase(oResponse.getStatus().toString(), "SUCCESS")
					&& oResponse.getInfo() == null) {
				Resources resources = oResponse.getResources();
				if (resources != null && resources.getResource() != null && resources.getResource().size() > 0) {
					Resource resource = resources.getResource().get(0);
					IdentificationData identificationData = resource.getUserIdentificationData();
					if (identificationData != null) {
						sessionInfo().setUnAuthenticatedUUID(new String(identificationData.getUUID().getValue()));
						sessionInfo().setUnAuthenticatedUserID(new String(identificationData.getUserName().getValue()));
						// logger.info("in /secure/user/list uuid:
						// "+sessionInfo().getUnAuthenticatedUUID());
						// logger.info("in /secure/user/list userid: "+optumId);
						identificationData.setUUID(null);
					}
					UserPayload userPayload = resource.getUserPayload();
					if (userPayload != null) {
						// logger.info("firstName :"+
						// resource.getUserPayload().getFirstName()+"lastName:
						// "+ resource.getUserPayload().getLastName());
						UserDetail userDetail = userPayload.getUserDetail();
						List<PhoneNumber> phoneNumbersList = userDetail.getPhoneNumbers();
						if (phoneNumbersList != null && phoneNumbersList.size() > 0) {

							for (PhoneNumber phoneNumber : phoneNumbersList) {
								// logger.info("in /secure/user/list
								// phoneNumber.getAreaCode()+phoneNumber.getAreaCode():
								// "+phoneNumber.getAreaCode()+phoneNumber.getAreaCode());
								sessionInfo().setMobileNumber(
										new String(phoneNumber.getAreaCode() + phoneNumber.getNumber()));
								sessionInfo().setMobileType(phoneNumber.getLabel().toString());
								// logger.info("in /secure/user/list
								// sessionInfo().getMobileNumber():
								// "+sessionInfo().getMobileNumber());
							}
						}
						List<EmailAddress> emailAddressList = userPayload.getEmails();
						if (emailAddressList != null && emailAddressList.size() > 0) {
							for (EmailAddress emailAddress : emailAddressList) {
								if (StringUtils.equalsIgnoreCase("Primary", emailAddress.getLabel().toString()))
									sessionInfo().setEmail(new String(emailAddress.getValue()));
								// logger.info("in /secure/user/list
								// sessionInfo().getEmail():
								// "+sessionInfo().getEmail());
							}
						}
					}
				}
			}
		} catch (InterruptedException | ExecutionException | IOException e) {
			e.printStackTrace();
		}

		return oResponse;
	}

	/*******************************************************************************************************************
	 * End of View
	 *******************************************************************************************************************/
	public void setFSOTokenForHttpRequest(HttpServletRequest request, String pmData) {
		if (StringUtils.isBlank(pmData)) {
			return;
		}
		if (request instanceof HttpServletRequest) {
			((HttpServletRequest) request).getSession(false).setAttribute("_FLASH_SO_", pmData);
		}
	}

	public void setFSOTokenForHttpResponse(HttpServletResponse response, String pmData) {
		if (StringUtils.isBlank(pmData)) {
			return;
		}
		if (response instanceof HttpServletRequest) {
			((HttpServletRequest) response).getSession(false).setAttribute("_FLASH_SO_", pmData);
		}
	}

	public void setDeviceCookie(HttpServletRequest request, HttpServletResponse response, String cookieValue,
			String appAlias) {
		if (StringUtils.isBlank(cookieValue)) {
			return;
		}

		if (response instanceof HttpServletResponse) {
			setDeviceCookie("aaData", cookieValue, (HttpServletRequest) request, (HttpServletResponse) response,
					appAlias);
		} else {
			return;
		}

	}

	private void setDeviceCookie(String devicecookiename, String cookieValue, HttpServletRequest request,
			HttpServletResponse response, String appAlias) {
		Cookie cookie = new Cookie(devicecookiename, cookieValue);
		cookie.setPath("/");
		cookie.setSecure(true);
		// cookie.setHttpOnly(false);
		// String domain = getCookieDomain(request);
		if (StringUtils.isNotBlank(appAlias) && StringUtils.equalsIgnoreCase(appAlias, "myu"))
			cookie.setDomain(".myuhc.com");
		else
			cookie.setDomain(".optum.com");
		/*
		 * if (domain != null) { cookie.setDomain(".optum.com"); }else{
		 * 
		 * cookie.setDomain(".optum.com"); }
		 */
		cookie.setMaxAge(365 * 24 * 60 * 60);
		response.addCookie(cookie);
	}

	private String getCookieDomain(HttpServletRequest request) {
		int cookieScope = 2;
		if (cookieScope == 0) {
			return null;
		}
		String serverName = request.getServerName();
		if (cookieScope == -1) {
			int seperator = serverName.indexOf(".");
			if (seperator < 0) {
				// logger.error(
				// "Server name {} isn't fully qualified, setting domain back to
				// null for the cookie for server defaults to take affect",
				// serverName);
				return null;
			}
			String domain = serverName.substring(seperator);
			// logger.debug("returning cookie domain as {}", domain);
			return domain;
		}

		// Ok so we have to work with cookie domain scope now.
		String[] hostNameParts = serverName.split("\\.");
		if (hostNameParts.length <= cookieScope) {
			return null;
		}
		int loc = hostNameParts.length - cookieScope;
		StringBuilder sBuilder = new StringBuilder();
		while (loc < hostNameParts.length) {
			sBuilder.append(".");
			sBuilder.append(hostNameParts[loc]);
			loc += 1;
		}
		String domain = sBuilder.toString();
		logger.info("the domain value is " + domain);
		return domain;
	}

	public void rememberUserDevice(String devicPrint, String uuid, String appAlias)
			throws InterruptedException, ExecutionException {
		Device deviceDetails = new Device();
		if (devicPrint != null && StringUtils.isNotBlank(devicPrint)) {
			String address = request.getHeader("X-Forwarded-For");
			if (StringUtils.isBlank(address)) {
				/*
				 * logger.warn(
				 * "IP Address is blank using header - '{}'. Defaulting to use HttpServletRequest Remote Address property"
				 * , address);
				 */
				deviceDetails.setHttpIpAddress(request.getRemoteAddr());
			} else {
				// check for multi-valued parameters
				if (address.contains(",")) {
					/*
					 * logger.
					 * warn("IP Address: {} from header: {}, will pick the first one before first comma"
					 * , new String[] {address, this.ipAddressHeaderName});
					 */
					try {
						address = address.split(",")[0].trim();
					} catch (Exception ex) {
						/*
						 * logger.
						 * error("Exception in parsing IP address {}, Exception details - \n{}"
						 * , new Object[] {address, ex});
						 */
						address = request.getRemoteAddr(); // use default!
					}
				}

				// set it now!
				deviceDetails.setHttpIpAddress(address);
			}

			// fail-safe check!
			if (StringUtils.isBlank(deviceDetails.getHttpIpAddress())) {
				deviceDetails.setHttpIpAddress(request.getRemoteAddr());
			}
			deviceDetails.setDevicePrint(devicPrint);
			deviceDetails.setHttpAccept(request.getHeader(ACCEPT_HEADER_NAME));
			deviceDetails.setHttpAcceptChars(request.getHeader(ACCEPT_CHARSET_HEADER_NAME));
			deviceDetails.setHttpAcceptEncoding(request.getHeader(ACCEPT_ENCODING_HEADER_NAME));
			deviceDetails.setHttpAcceptLanguage(request.getHeader(ACCEPT_LANGUAGE_HEADER_NAME));
			deviceDetails.setHttpRefferer(request.getHeader(REFERER_HEADER_NAME));
			deviceDetails.setHttpUserAgent(request.getHeader(USER_AGENT_HEADER_NAME));
			deviceDetails.setUserName(uuid);
			AddDeviceResponse addDeviceResponse = healthSafeIdService.addUserDevice(deviceDetails).get();
			if (addDeviceResponse != null) {
				// setFSOTokenForHttpRequest(request, ((AddDeviceResponse)
				// addDeviceResponse).getDeviceSFOToken());
				setFSOTokenForHttpResponse(response, ((AddDeviceResponse) addDeviceResponse).getDeviceSFOToken());
				setDeviceCookie(request, response, ((AddDeviceResponse) addDeviceResponse).getDeviceCookie(), appAlias);
				// logger.info("FSOToken Request value "+
				// request.getSession().getAttribute("_FLASH_SO_"));
				// logger.info("FSOToken Response value "+
				// request.getSession().getAttribute("_FLASH_SO_"));
			}
		}
	}

	public static String getLang(SessionInfoWrapper sessionInfoWrapper) {
		if (sessionInfoWrapper != null && sessionInfoWrapper.getInboundParameter() != null
				&& sessionInfoWrapper.getInboundParameter().getLanguage() != null
				&& sessionInfoWrapper.getInboundParameter().getLanguage().name() != null) {

			return sessionInfoWrapper.getInboundParameter().getLanguage().name().toLowerCase();
		} else {
			return "en";
		}
	}

	private boolean isTargetUrlValid(AppConstants.ACTION action, PortalDestinationType targetPortal, String targetUrl) {

		logger.info("In isTargetUrlValid method action-- " + action + " targetPortal-- " + targetPortal.name()
				+ " targetUrl-- " + targetUrl);
		final String VALIDTARGETDOMAIN = "Validtargetdomains\":\"&lt;p&gt;[";
		boolean valid = false;
		String content = contentController.getContent(null, targetPortal.name(), action.name());
		if (StringUtils.containsIgnoreCase(targetPortal.name(), "GEHUB")
				&& (StringUtils.isBlank(targetUrl) || "null".equalsIgnoreCase(targetUrl))) {
			valid = true;
		}
		if (StringUtils.isNotBlank(content)) {

			if (StringUtils.containsIgnoreCase(content, VALIDTARGETDOMAIN)) {

				String domainsString = StringUtils.substringBetween(content, VALIDTARGETDOMAIN, "]");

				if (StringUtils.isNotBlank(domainsString)) {

					String tokens = StringUtils.lowerCase(
							StringUtils.replace(StringUtils.replace(domainsString, "&amp;quot;", ""), " ", ""));

					try {

						URL originTarget = new URL(targetUrl);
						List<String> tokensList = Arrays.asList(StringUtils.split(tokens, ","));
						for (String string : tokensList) {
							if (StringUtils.contains(string, "*")) {
								StringUtils.containsIgnoreCase(originTarget.getHost(),
										StringUtils.replace(string, "*", ""));
								valid = true;
								break;
							}
							if (StringUtils.containsIgnoreCase(string, StringUtils.lowerCase(originTarget.getHost()))) {
								valid = true;
								break;
							}
						}
					} catch (Exception e) {
						logger.info("in method isTargetUrlValid: the targetUrl is not valid format");
					}
				}
			}

		}

		// blocked by content service
		return valid;
	}

}
