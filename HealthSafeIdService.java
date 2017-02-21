/**
* 
*/
package com.optum.ogn.service;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.logging.Logger;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixProperty;
import com.netflix.hystrix.contrib.javanica.command.AsyncResult;
import com.optum.ogn.app.AppConstants;
import com.optum.ogn.app.ConnectionSettings;
import com.optum.ogn.app.ExternalIntegrationConfiguration;
import com.optum.ogn.domain.healthsafe.UserAudit;
import com.optum.ogn.iam.model.AccountStatus.PasswordStatusEnum;
import com.optum.ogn.iam.model.AddApplicationAccessRequest;
import com.optum.ogn.iam.model.AddIRMAuditLogEventRequest;
import com.optum.ogn.iam.model.AddUserResponse;
import com.optum.ogn.iam.model.AuditLogEvent;
import com.optum.ogn.iam.model.AuditLogEvent.ActivityEnum;
import com.optum.ogn.iam.model.AuditLogEvent.LogLevelEnum;
import com.optum.ogn.iam.model.ChallengeResponseQuestion;
import com.optum.ogn.iam.model.Credential;
import com.optum.ogn.iam.model.Credential.TypesEnum;
import com.optum.ogn.iam.model.Device;
import com.optum.ogn.iam.model.EmailAddress;
import com.optum.ogn.iam.model.EmailAddress.AttributeActionTypeEnum;
import com.optum.ogn.iam.model.Error;
import com.optum.ogn.iam.model.ErrorMessage;
import com.optum.ogn.iam.model.Errors;
import com.optum.ogn.iam.model.Filter;
import com.optum.ogn.iam.model.IdentificationData;
import com.optum.ogn.iam.model.ModificationActionTypeList;
import com.optum.ogn.iam.model.ModificationActionTypeList.ActionTypesEnum;
import com.optum.ogn.iam.model.OnBehalfOf;
import com.optum.ogn.iam.model.PasswordV2Parameters;
import com.optum.ogn.iam.model.PhoneNumber;
import com.optum.ogn.iam.model.PhoneNumber.LabelEnum;
import com.optum.ogn.iam.model.Resource;
import com.optum.ogn.iam.model.Resources;
import com.optum.ogn.iam.model.Response;
import com.optum.ogn.iam.model.SearchArguments;
import com.optum.ogn.iam.model.SearchParameters;
import com.optum.ogn.iam.model.User;
import com.optum.ogn.iam.model.UserDetail;
import com.optum.ogn.iam.model.UserLookupRequest;
import com.optum.ogn.iam.model.UserName;
import com.optum.ogn.iam.model.UserPayload;
import com.optum.ogn.model.AddDeviceResponse;
import com.optum.ogn.model.AddUserRequest;
import com.optum.ogn.model.CheckUserNameResponse;
import com.optum.ogn.model.CheckUserNameResponse.StatusEnum;
import com.optum.ogn.model.ProvisionRequest;
import com.optum.ogn.model.SessionInfoWrapper;
import com.optum.ogn.provision.model.GetMemberAttrResponse;
import com.optum.ogn.util.AuthenticationHelper;

/**
 * @author srikanth dugyala
 *
 */
@Service
public class HealthSafeIdService {

	private final class AdminUserInfo extends AsyncResult<Response> {
		private final String userId;

		private AdminUserInfo(String userId) {
			this.userId = userId;
		}

		@SuppressWarnings("unchecked")
		@Override
		public Response invoke() {
			logger.info("in getUserFiltereList resulting in no SQ userlist");
			String response = "";
			Response user = null;
			try {
				response = ConnectionSettings
						.getSecureRestClient(
								ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
										+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
						.getAsJson(String.class);
				ObjectMapper mapper = new ObjectMapper();
				mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
				mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
				user = mapper.readValue(response, Response.class);
				if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
						&& user.getInfo() == null) {
					Resources resources = user.getResources();
					if (resources != null && resources.getResource() != null && resources.getResource().size() > 0) {

						Resource resource = resources.getResource().get(0);
						UserPayload userPayload = resource.getUserPayload();
						if (userPayload != null) {
							logger.info("firstName :" + resource.getUserPayload().getFirstName() + "lastName: "
									+ resource.getUserPayload().getLastName());
							UserDetail userDetail = userPayload.getUserDetail();
							if (userDetail.getCredential() != null
									&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
									&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {

								List<ChallengeResponseQuestion> challengeResponseQuestions = userDetail.getCredential()
										.getSecurityQuestionAndAnswers();
								challengeResponseQuestions.clear();
							}

						}
					}

				} else if (StringUtils.containsIgnoreCase(response, "error")) {
					List<com.optum.ogn.iam.model.Error> errorList = user.getErrors().getError();
					for (com.optum.ogn.iam.model.Error error : errorList) {
						String des = error.getDescription();
						error.setDescription(des.replaceFirst("\"\"", "\"" + userId + "\""));
					}
				}
			} catch (RestClientException | IOException e) {
				e.printStackTrace();
			}
			return user;
		}
	}

	private Logger logger = Logger.getLogger(HealthSafeIdService.class.getName());

	@Autowired
	private SessionInfoWrapper sessionInfo;

	@Inject
	private ExternalIntegrationConfiguration externalIntegrationConfiguration;

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getProfileById", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Map<String, Boolean>> getProfileById(final String userId) {
		return new AsyncResult<Map<String, Boolean>>() {
			@SuppressWarnings("unchecked")
			@Override
			public Map<String, Boolean> invoke() {

				HashMap<String, String> payLoad = new HashMap<>();
				MultiValueMap<String, String> headers = new LinkedMultiValueMap<String, String>();
				headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				Map<String, Boolean> result = new HashMap<String, Boolean>();
				result.put("isEmailAvailable", false);
				result.put("isEmailVerified", false);
				result.put("isPhoneAvailable", false);
				result.put("isPhoneVerified", false);
				result.put("isUserLocked", false);
				result.put("isSecurityQsAvailable", false);
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								// logger.info("firstName :"+
								// userPayload.getFirstName()+"lastName: "+
								// userPayload.getLastName());
								List<EmailAddress> emailList = userPayload.getEmails();
								if (emailList != null && emailList.size() > 0) {
									for (EmailAddress emailAddress : emailList) {

										if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
											result.remove("isEmailAvailable");
											result.put("isEmailAvailable", true);
											result.remove("isEmailVerified");
											result.put("isEmailVerified", emailAddress.getVerified());
										}
									}
								}
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail != null) {
									List<PhoneNumber> phoneList = userDetail.getPhoneNumbers();
									if (phoneList != null && phoneList.size() > 0) {
										for (PhoneNumber phoneNumber : phoneList) {

											if (StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
													"MOBILE")
													|| StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
															"HOME")) {
												result.remove("isPhoneAvailable");
												result.put("isPhoneAvailable", true);
												result.remove("isPhoneVerified");
												result.put("isPhoneVerified", phoneNumber.getVerified());
											}
										}
									}
									if (userDetail.getUserAccountStatus() != null
											&& userDetail.getUserAccountStatus().getPasswordStatus() != null
											&& !StringUtils.equalsIgnoreCase(
													userDetail.getUserAccountStatus().getPasswordStatus().toString(),
													PasswordStatusEnum.ACTIVE.toString())) {
										result.remove("isUserLocked");
										result.put("isUserLocked", true);
									}

									if (userDetail.getCredential() != null
											&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
											&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {
										result.remove("isSecurityQsAvailable");
										result.put("isSecurityQsAvailable", true);
									}
								}
							}

						}
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return result;
			}
		};
	}

	@Inject
	ProvisionDataStoreService ProvisionDataStoreService;

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getIdByEmail", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> getID(final Map<String, String> filterMap) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {

				String emailString = ((filterMap.get("email")));
				String firstNameString = filterMap.get("firstName");
				String lastNameString = filterMap.get("lastName");
				String dateOfBirth = filterMap.get("dateOfBirth");
				if (StringUtils.isBlank(dateOfBirth))
					dateOfBirth = filterMap.get("dob");
				String phone = filterMap.get("phone");
				Filter filter = null;

				SearchArguments searchArguments = new SearchArguments();
				ArrayList<Filter> filterList = new ArrayList<Filter>();

				if (emailString != null) {

					filter = new Filter();
					filter.setKey("emails");
					filter.setValue(((filterMap.get("email"))));
					filterList.add(filter);
				}

				if (firstNameString != null) {

					filter = new Filter();
					filter.setKey("firstName");
					filter.setValue(filterMap.get("firstName"));
					filterList.add(filter);
				}

				if (lastNameString != null) {

					filter = new Filter();
					filter.setKey("lastName");
					filter.setValue(filterMap.get("lastName"));
					filterList.add(filter);
				}
				if (dateOfBirth != null) {

					filter = new Filter();
					filter.setKey("dateOfBirth");
					filter.setValue(dateOfBirth);
					filterList.add(filter);
				}
				if (phone != null) {
					Filter filter1 = new Filter();
					filter1.setKey("phoneNumbers.areaCode");
					filter1.setValue(phone.substring(0, 3));
					filterList.add(filter1);

					Filter filter2 = new Filter();
					filter2.setKey("phoneNumbers.number");
					filter2.setValue(phone.substring(3, 10));
					filterList.add(filter2);

					Filter filter3 = new Filter();
					filter3.setKey("phoneNumbers.label");
					filter3.setValue("MOBILE");
					filterList.add(filter3);

					Filter filter4 = new Filter();
					filter4.setKey("phoneNumbers.countryCode");
					filter4.setValue("1");
					filterList.add(filter4);
				}

				searchArguments.setFilter(filterList);
				SearchParameters parameters = new SearchParameters();
				parameters.setSearcharguments(searchArguments);
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<SearchParameters>(parameters,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByEmailRes()),
					// HttpMethod.POST, request, String.class);
					// response = restTemplate.exchange(new
					// URI("http://healthsafeidservices10-wdtdev1.ose.optum.com/api/secure/v1/user/lookup"),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByEmailRes())
							.postJson(parameters, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					String uuid = null;
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() == 1) {
							Resource resource = resources.getResource().get(0);
							IdentificationData data = resource.getUserIdentificationData();
							if (data != null) {
								logger.info("username : " + data.getUserName().getValue());
								return data.getUserName().getValue();
							}

							// For more than one user
						} else if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 1) {
							ArrayList<ProvisionRequest> provisionlist = new ArrayList<>();
							ProvisionRequest request = new ProvisionRequest();
							for (Resource resourceList : resources.getResource()) {
								uuid = resourceList.getUserIdentificationData().getUUID().getValue();
								String userName = resourceList.getUserIdentificationData().getUserName().getValue();
								request.setOptumId(uuid);
								provisionlist.add(request);
								filterMap.put(uuid, userName);
							}
							if (!provisionlist.isEmpty() && ProvisionDataStoreService != null) {
								List<GetMemberAttrResponse> memberlist = ProvisionDataStoreService
										.getMembers(provisionlist, false).get();
								if (memberlist == null || memberlist.size() == 0) {
									// No record found case
									return userNotFoundError();
								} else if (memberlist.size() > 1) {
									// ask for customer care
									com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
									error.setCode("404");
									error.setDescription("Multiple User Accounts Found, try by adding more filters");
									return error;
								} else {
									// means found valid customer
									GetMemberAttrResponse attrResponse = memberlist.get(0);

									String validUuid = attrResponse.getHealthSafeId();
									// retun username
									if (validUuid != null) {
										String username = filterMap.get(validUuid);
										logger.info("Result Username from more than one username " + username);
										return username;
									}
								}
							}
						}
					} else {
						return internalServerException();
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ExecutionException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return internalServerException();
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "findSharedEmailCount", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> findSharedEmailCount(final Map<String, String> filterMap, final boolean onlyEmail) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {

				String emailString = ((filterMap.get("email")));
				String firstNameString = filterMap.get("firstName");
				String lastNameString = filterMap.get("lastName");
				String dateOfBirth = filterMap.get("dateOfBirth");
				if (StringUtils.isBlank(dateOfBirth))
					dateOfBirth = filterMap.get("dob");
				String phone = filterMap.get("phone");
				Filter filter = null;

				SearchArguments searchArguments = new SearchArguments();
				ArrayList<Filter> filterList = new ArrayList<Filter>();

				if (emailString != null) {

					filter = new Filter();
					filter.setKey("emails");
					filter.setValue(((filterMap.get("email"))));
					filterList.add(filter);
				}
				if (!onlyEmail) {

					if (firstNameString != null) {

						filter = new Filter();
						filter.setKey("firstName");
						filter.setValue(filterMap.get("firstName"));
						filterList.add(filter);
					}

					if (lastNameString != null) {

						filter = new Filter();
						filter.setKey("lastName");
						filter.setValue(filterMap.get("lastName"));
						filterList.add(filter);
					}
					if (dateOfBirth != null) {

						filter = new Filter();
						filter.setKey("dateOfBirth");
						filter.setValue(dateOfBirth);
						filterList.add(filter);
					}
					if (phone != null) {
						Filter filter1 = new Filter();
						filter1.setKey("phoneNumbers.areaCode");
						filter1.setValue(phone.substring(0, 3));
						filterList.add(filter1);

						Filter filter2 = new Filter();
						filter2.setKey("phoneNumbers.number");
						filter2.setValue(phone.substring(3, 10));
						filterList.add(filter2);

						Filter filter3 = new Filter();
						filter3.setKey("phoneNumbers.label");
						filter3.setValue("MOBILE");
						filterList.add(filter3);

						Filter filter4 = new Filter();
						filter4.setKey("phoneNumbers.countryCode");
						filter4.setValue("1");
						filterList.add(filter4);
					}
				}
				searchArguments.setFilter(filterList);
				SearchParameters parameters = new SearchParameters();
				parameters.setSearcharguments(searchArguments);
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<SearchParameters>(parameters,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByEmailRes()),
					// HttpMethod.POST, request, String.class);
					// response = restTemplate.exchange(new
					// URI("http://healthsafeidservices10-wdtdev1.ose.optum.com/api/secure/v1/user/lookup"),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByEmailRes())
							.postJson(parameters, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					String uuid = null;
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null) {
							return resources.getResource().size();
						}
					}
					// should have sent error code
					return internalServerException();

				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				return internalServerException();
			}
		};
	}

	private Error internalServerException() {
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("500");
		error.setDescription("Internal Server Exception");
		return error;
	}

	private Error userNotFoundError() {
		com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
		error.setCode("400");
		error.setDescription("Userid not found");
		return error;
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "updateUser", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> updateUser(final String userProfile, final Map<String, String> payLoad, final String userId,
			final String targetPortal, final String source, final boolean isFromRegistration, final String lang) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				boolean isUpdated = false;
				String newEmail = "";
				String oldEmail = "";
				String isVerified = payLoad.get("isverified");
				// HashMap<String, String> body = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(body,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				try {
					// response = restTemplate.getForEntity(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response.replace("1970-01-01", "1970-01-02"), Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {
							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								// logger.info("firstName :"+
								// resource.getUserPayload().getFirstName()+"lastName:
								// "+ resource.getUserPayload().getLastName());
								List<EmailAddress> emailList = userPayload.getEmails();
								if (emailList.size() > 1
										&& ((StringUtils.equalsIgnoreCase(emailList.get(0).getValue(),
												payLoad.get("email"))
												&& !StringUtils.equalsIgnoreCase(emailList.get(0).getLabel(),
														payLoad.get("type")))
												|| (StringUtils.equalsIgnoreCase(emailList.get(1).getValue(),
														payLoad.get("email"))
														&& !StringUtils.equalsIgnoreCase(
																emailList.get(1).getLabel(), payLoad.get("type"))))
										&& StringUtils.equalsIgnoreCase(userProfile, "email")) {
									com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
									error.setCode("400");
									error.setDescription("[\nEmail address should not be duplicate\n]");
									return error;

								}
								if (emailList != null && emailList.size() > 0) {
									for (EmailAddress emailAddress : emailList) {
										if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), payLoad.get("type"))
												&& StringUtils.equalsIgnoreCase(userProfile, "email")) {
											if (emailAddress.getVerified())
												oldEmail = new String(emailAddress.getValue());
											emailAddress.setAttributeActionType(AttributeActionTypeEnum.MODIFY);
											emailAddress.setDefault(false);
											emailAddress.setLabel(payLoad.get("type"));
											emailAddress.setVerified(false);
											emailAddress.setValue(payLoad.get("email"));
											ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
											List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
											actionTypes.add(ActionTypesEnum.EMAILS);
											modificationActionTypeList.setActionTypes(actionTypes);
											resource.setModificationActionTypeList(modificationActionTypeList);
											resource.setResultItems(null);
											resource.setSuggestedUsernames(null);
											// headers = new
											// LinkedMultiValueMap<String,
											// String>();
											// headers.add("Accept",
											// MediaType.APPLICATION_JSON.toString());
											mapper.setSerializationInclusion(Include.NON_NULL);
											// request = new
											// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
											// User.class),headers);
											// response =
											// restTemplate.exchange(new
											// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
											// HttpMethod.PUT, request,
											// String.class);
											response = ConnectionSettings
													.getSecureRestClient(ConnectionSettings.getIamServer()
															+ ConnectionSettings.getIamProfileUpdateRes())
													.putJson(mapper.readValue(mapper.writeValueAsString(resource),
															User.class), String.class);
											/*
											 * if(!StringUtils.
											 * containsIgnoreCase(response,
											 * "Error")){ emailAddress.
											 * setAttributeActionType(
											 * AttributeActionTypeEnum.ADD);
											 * emailAddress.setDefault(false);
											 * emailAddress.setLabel(payLoad.get
											 * ("type"));
											 * emailAddress.setVerified(false);
											 * emailAddress.setValue(payLoad.get
											 * ("email")); // request = new
											 * HttpEntity<User>(mapper.readValue
											 * (mapper.writeValueAsString(
											 * resource), User.class),headers);
											 * // response =
											 * restTemplate.exchange(new
											 * URI(ConnectionSettings.
											 * getIamServer()+ConnectionSettings
											 * .getIamProfileUpdateRes()),
											 * HttpMethod.PUT, request,
											 * String.class); response =
											 * ConnectionSettings.getRestClient(
											 * ConnectionSettings.getIamServer()
											 * +ConnectionSettings.
											 * getIamProfileUpdateRes()).putJson
											 * (mapper.readValue(mapper.
											 * writeValueAsString(resource),
											 * User.class), String.class);
											 * if(StringUtils.containsIgnoreCase
											 * (response, "Error")){
											 * emailAddress.
											 * setAttributeActionType(
											 * AttributeActionTypeEnum.ADD);
											 * emailAddress.setDefault(false);
											 * emailAddress.setLabel(payLoad.get
											 * ("type"));
											 * emailAddress.setVerified(false);
											 * emailAddress.setValue(oldEmail);
											 * // request = new
											 * HttpEntity<User>(mapper.readValue
											 * (mapper.writeValueAsString(
											 * resource), User.class),headers);
											 * // response =
											 * restTemplate.exchange(new
											 * URI(ConnectionSettings.
											 * getIamServer()+ConnectionSettings
											 * .getIamProfileUpdateRes()),
											 * HttpMethod.PUT, request,
											 * String.class); response =
											 * ConnectionSettings.getRestClient(
											 * ConnectionSettings.getIamServer()
											 * +ConnectionSettings.
											 * getIamProfileUpdateRes()).putJson
											 * (mapper.readValue(mapper.
											 * writeValueAsString(resource),
											 * User.class), String.class); } }
											 */
											isUpdated = true;
											break;

										}
									}
									if (!isUpdated && (StringUtils.equalsIgnoreCase("Primary", payLoad.get("type"))
											|| StringUtils.equalsIgnoreCase("Secondary", payLoad.get("type")))) {

										EmailAddress emailAddress1 = new EmailAddress();
										emailAddress1.setAttributeActionType(AttributeActionTypeEnum.ADD);
										emailAddress1.setDefault(false);
										emailAddress1.setLabel(payLoad.get("type"));
										emailAddress1.setVerified(false);
										emailAddress1.setValue(payLoad.get("email"));
										emailList.add(emailAddress1);
										ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
										List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
										actionTypes.add(ActionTypesEnum.EMAILS);
										modificationActionTypeList.setActionTypes(actionTypes);
										resource.setModificationActionTypeList(modificationActionTypeList);
										resource.setResultItems(null);
										resource.setSuggestedUsernames(null);
										// headers = new
										// LinkedMultiValueMap<String,
										// String>();
										// headers.add("Accept",
										// MediaType.APPLICATION_JSON.toString());
										mapper.setSerializationInclusion(Include.NON_NULL);
										// request = new
										// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
										// User.class),headers);
										// response = restTemplate.exchange(new
										// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
										// HttpMethod.PUT, request,
										// String.class);
										response = ConnectionSettings
												.getSecureRestClient(ConnectionSettings.getIamServer()
														+ ConnectionSettings.getIamProfileUpdateRes())
												.putJson(mapper.readValue(mapper.writeValueAsString(resource),
														User.class), String.class);

									}

								} else if (StringUtils.equalsIgnoreCase("Primary", payLoad.get("type"))
										|| StringUtils.equalsIgnoreCase("Secondary", payLoad.get("type"))) {
									List<EmailAddress> newEmailList = new ArrayList<EmailAddress>();
									EmailAddress emailAddress1 = new EmailAddress();
									emailAddress1.setAttributeActionType(AttributeActionTypeEnum.ADD);
									emailAddress1.setDefault(false);
									emailAddress1.setLabel(payLoad.get("type"));
									emailAddress1.setVerified(false);
									emailAddress1.setValue(payLoad.get("email"));
									newEmailList.add(emailAddress1);
									userPayload.setEmails(newEmailList);
									ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
									List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
									actionTypes.add(ActionTypesEnum.EMAILS);
									modificationActionTypeList.setActionTypes(actionTypes);
									resource.setModificationActionTypeList(modificationActionTypeList);
									resource.setResultItems(null);
									resource.setSuggestedUsernames(null);
									// headers = new LinkedMultiValueMap<String,
									// String>();
									// headers.add("Accept",
									// MediaType.APPLICATION_JSON.toString());
									mapper.setSerializationInclusion(Include.NON_NULL);
									// request = new
									// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
									// User.class),headers);
									// response = restTemplate.exchange(new
									// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
									// HttpMethod.PUT, request, String.class);
									response = ConnectionSettings
											.getSecureRestClient(ConnectionSettings.getIamServer()
													+ ConnectionSettings.getIamProfileUpdateRes())
											.putJson(mapper.readValue(mapper.writeValueAsString(resource), User.class),
													String.class);

								}
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail != null) {
									List<PhoneNumber> phoneList = userDetail.getPhoneNumbers();
									/*
									 * if(phoneList.size()>2){ String phone1 =
									 * new
									 * StringBuilder().append(phoneList.get(0).
									 * getAreaCode())
									 * .append(phoneList.get(0).getNumber()).
									 * toString() ; String phone2 = new
									 * StringBuilder().append(phoneList.get(1).
									 * getAreaCode())
									 * .append(phoneList.get(1).getNumber()).
									 * toString() ; String phone3 = new
									 * StringBuilder().append(phoneList.get(2).
									 * getAreaCode())
									 * .append(phoneList.get(2).getNumber()).
									 * toString() ;
									 * if(StringUtils.equalsIgnoreCase(phone1,
									 * phone2)
									 * ||StringUtils.equalsIgnoreCase(phone2,
									 * phone3)
									 * ||StringUtils.equalsIgnoreCase(phone1,
									 * phone3)){
									 * if(StringUtils.equalsIgnoreCase(phone1,
									 * payLoad.get("type"))
									 * ||StringUtils.equalsIgnoreCase(phone2,
									 * payLoad.get("type"))){
									 * com.optum.ogn.iam.model.Error error = new
									 * com.optum.ogn.iam.model.Error();
									 * error.setCode("400"); error.
									 * setDescription("cannot add duplicate numbers"
									 * ); return error; }
									 * 
									 * } }
									 */
									if (phoneList != null && phoneList.size() > 0) {
										for (PhoneNumber phoneNumber : phoneList) {

											if (StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
													payLoad.get("type"))
													&& StringUtils.equalsIgnoreCase(userProfile, "phone")) {
												String phone = payLoad.get("phone");
												if (phone != null) {
													phoneNumber.setAttributeActionType(
															com.optum.ogn.iam.model.PhoneNumber.AttributeActionTypeEnum.MODIFY);
													phoneNumber.setAreaCode(phone.substring(0, 3));
													phoneNumber.setCountryCode("1");
													phoneNumber.setNumber(phone.substring(3));
													phoneNumber.setLabel(
															PhoneNumber.LabelEnum.valueOf(payLoad.get("type")));
													phoneNumber.setVerified(false);
													ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
													List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
													actionTypes.add(ActionTypesEnum.PHONES);
													modificationActionTypeList.setActionTypes(actionTypes);
													resource.setModificationActionTypeList(modificationActionTypeList);
													resource.setResultItems(null);
													resource.setSuggestedUsernames(null);
													// headers = new
													// LinkedMultiValueMap<String,
													// String>();
													// headers.add("Accept",
													// MediaType.APPLICATION_JSON.toString());
													mapper.setSerializationInclusion(Include.NON_NULL);
													// request = new
													// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
													// User.class),headers);
													// response =
													// restTemplate.exchange(new
													// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
													// HttpMethod.PUT, request,
													// String.class);
													response = ConnectionSettings
															.getRestClient(ConnectionSettings.getIamServer()
																	+ ConnectionSettings.getIamProfileUpdateRes())
															.putJson(mapper.readValue(
																	mapper.writeValueAsString(resource), User.class),
																	String.class);

													/*
													 * if(!StringUtils.
													 * containsIgnoreCase(
													 * response, "Error")){
													 * phoneNumber.setAreaCode(
													 * phone.substring(0, 3));
													 * phoneNumber.
													 * setCountryCode("1");
													 * phoneNumber.setNumber(
													 * phone.substring(3));
													 * phoneNumber.setLabel(
													 * PhoneNumber.LabelEnum.
													 * valueOf(payLoad.get(
													 * "type")));
													 * phoneNumber.setVerified(
													 * false); phoneNumber.
													 * setAttributeActionType(
													 * com.optum.ogn.iam.model.
													 * PhoneNumber.
													 * AttributeActionTypeEnum.
													 * ADD); // request = new
													 * HttpEntity<User>(mapper.
													 * readValue(mapper.
													 * writeValueAsString(
													 * resource),
													 * User.class),headers); //
													 * response =
													 * restTemplate.exchange(new
													 * URI(ConnectionSettings.
													 * getIamServer()+
													 * ConnectionSettings.
													 * getIamProfileUpdateRes())
													 * , HttpMethod.PUT,
													 * request, String.class);
													 * response =
													 * ConnectionSettings.
													 * getRestClient(
													 * ConnectionSettings.
													 * getIamServer()+
													 * ConnectionSettings.
													 * getIamProfileUpdateRes())
													 * .putJson(mapper.readValue
													 * (mapper.
													 * writeValueAsString(
													 * resource), User.class),
													 * String.class); }
													 */
													isUpdated = true;
													break;
												}
											}
										}
										if (!isUpdated && (StringUtils.equalsIgnoreCase(
												PhoneNumber.LabelEnum.HOME.toString(), payLoad.get("type"))
												|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.MOBILE.toString(),
														payLoad.get("type"))
												|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.WORK.toString(),
														payLoad.get("type")))) {
											PhoneNumber phoneNumber1 = new PhoneNumber();
											String phone = payLoad.get("phone");
											if (phone != null) {
												phoneNumber1.setAreaCode(phone.substring(0, 3));
												phoneNumber1.setCountryCode("1");
												phoneNumber1.setNumber(phone.substring(3));
												phoneNumber1
														.setLabel(PhoneNumber.LabelEnum.valueOf(payLoad.get("type")));
												phoneNumber1.setVerified(false);
												phoneNumber1.setAttributeActionType(
														com.optum.ogn.iam.model.PhoneNumber.AttributeActionTypeEnum.ADD);
												userDetail.getPhoneNumbers().add(phoneNumber1);
												ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
												List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
												actionTypes.add(ActionTypesEnum.PHONES);
												modificationActionTypeList.setActionTypes(actionTypes);
												resource.setModificationActionTypeList(modificationActionTypeList);
												resource.setResultItems(null);
												resource.setSuggestedUsernames(null);
												// headers = new
												// LinkedMultiValueMap<String,
												// String>();
												// headers.add("Accept",
												// MediaType.APPLICATION_JSON.toString());
												mapper.setSerializationInclusion(Include.NON_NULL);
												// request = new
												// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
												// User.class),headers);
												// response =
												// restTemplate.exchange(new
												// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
												// HttpMethod.PUT, request,
												// String.class);
												response = ConnectionSettings
														.getSecureRestClient(ConnectionSettings.getIamServer()
																+ ConnectionSettings.getIamProfileUpdateRes())
														.putJson(mapper.readValue(mapper.writeValueAsString(resource),
																User.class), String.class);
											}

										}
									} else if (StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.HOME.toString(),
											payLoad.get("type"))
											|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.MOBILE.toString(),
													payLoad.get("type"))
											|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.WORK.toString(),
													payLoad.get("type"))) {
										List<PhoneNumber> phoneList1 = new ArrayList<PhoneNumber>();
										PhoneNumber phoneNumber1 = new PhoneNumber();
										String phone = payLoad.get("phone");
										if (phone != null) {
											phoneNumber1.setAreaCode(phone.substring(0, 3));
											phoneNumber1.setCountryCode("1");
											phoneNumber1.setNumber(phone.substring(3));
											phoneNumber1.setLabel(PhoneNumber.LabelEnum.valueOf(payLoad.get("type")));
											phoneNumber1.setVerified(false);
											phoneNumber1.setAttributeActionType(
													com.optum.ogn.iam.model.PhoneNumber.AttributeActionTypeEnum.ADD);
											phoneList1.add(phoneNumber1);
											userDetail.setPhoneNumbers(phoneList1);
											ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
											List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
											actionTypes.add(ActionTypesEnum.PHONES);
											modificationActionTypeList.setActionTypes(actionTypes);
											resource.setModificationActionTypeList(modificationActionTypeList);
											resource.setResultItems(null);
											resource.setSuggestedUsernames(null);
											// headers = new
											// LinkedMultiValueMap<String,
											// String>();
											// headers.add("Accept",
											// MediaType.APPLICATION_JSON.toString());
											mapper.setSerializationInclusion(Include.NON_NULL);
											// request = new
											// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
											// User.class),headers);
											// response =
											// restTemplate.exchange(new
											// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
											// HttpMethod.PUT, request,
											// String.class);
											response = ConnectionSettings
													.getRestClient(ConnectionSettings.getIamServer()
															+ ConnectionSettings.getIamProfileUpdateRes())
													.putJson(mapper.readValue(mapper.writeValueAsString(resource),
															User.class), String.class);
										}
									}
								}

							}
						}
						if (StringUtils.containsIgnoreCase(response, "Error")) {
							ObjectMapper objectMapper = new ObjectMapper();
							JsonNode rootNode;
							rootNode = objectMapper.readTree(AuthenticationHelper.validateContent(response));
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("400");
							error.setDescription(
									rootNode.get("errors").get("Error").get(0).get("description").textValue());
							return error;
						} else {
							Response emailResponse = mapper.readValue(response, Response.class);
							if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
									&& user.getInfo() == null) {
								Resources resources1 = user.getResources();
								if (resources1 != null && resources1.getResource() != null
										&& resources1.getResource().size() > 0) {
									Resource resource = resources1.getResource().get(0);
									UserPayload userPayload = resource.getUserPayload();
									if (userPayload != null) {
										List<EmailAddress> emailList = userPayload.getEmails();
										if (emailList != null && emailList.size() > 0) {
											for (EmailAddress emailAddress : emailList) {
												if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
													newEmail = emailAddress.getValue();
												}

											}
										}
									}
								}
							}

							if (((StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.HOME.toString(),
									payLoad.get("type"))
									|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.MOBILE.toString(),
											payLoad.get("type"))
									|| StringUtils.equalsIgnoreCase(PhoneNumber.LabelEnum.WORK.toString(),
											payLoad.get("type")))
									&& !StringUtils.equalsIgnoreCase(isVerified, "false")) && !isFromRegistration) {
								String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
										.append(ConnectionSettings.getIamForgetuserName()).append("phone")
										.append("?to=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(newEmail)))
										.append("&username=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
										.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=")
										.append(targetPortal).append("&")
										.append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
										.append(targetPortal).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE)
										.append("=").append(lang).append("&userid=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
										.toString();
								ConnectionSettings.getRestClient(emailUrl.trim()).getAsJson(String.class);

							}
							if (StringUtils.isNotBlank(oldEmail)
									&& (StringUtils.equalsIgnoreCase("Primary", payLoad.get("type"))
											|| StringUtils.equalsIgnoreCase("Secondary", payLoad.get("type")))) {
								String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
										.append(ConnectionSettings.getIamForgetuserName()).append("newmail")
										.append("?to=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(oldEmail)))
										.append("&username=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
										.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=")
										.append(targetPortal).append("&")
										.append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
										.append(targetPortal).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE)
										.append("=").append(lang).append("&userid=")
										.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
										.toString();
								ConnectionSettings.getRestClient(emailUrl.trim()).getAsJson(String.class);

							}
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("200");
							error.setDescription(userProfile + " is successfully updated");
							return error;
						}

					} else {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Userid not found");
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "setPassword", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> setPassword(final String userProfile, final Map<String, String> payLoad, final String userId,
			final String targetPortal, final String targetBrand, final String lang) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				PasswordV2Parameters passwordV2Parameters = new PasswordV2Parameters();
				passwordV2Parameters.setNewpassword(payLoad.get("newpassword"));
				if (StringUtils.isNotBlank(payLoad.get("oldpassword"))) {
					passwordV2Parameters.setOldpassword(payLoad.get("oldpassword"));
				}
				;
				passwordV2Parameters.setUserid(userId);

				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<PasswordV2Parameters>(passwordV2Parameters,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamPasswordRes()),
					// HttpMethod.PUT, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamPasswordRes())
							.putJson(passwordV2Parameters, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response.replace("1970-01-01", "1970-01-02"), Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {

						String url = ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
								+ java.net.URLEncoder.encode(StringUtils.defaultString(userId));
						// String content = new
						// RestTemplate().getForObject(url.trim(),String.class);
						String content = ConnectionSettings.getSecureRestClient(url.trim()).getAsJson(String.class);
						user = mapper.readValue(content, Response.class);
						if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
								&& user.getInfo() == null) {
							Resources resources = user.getResources();
							if (resources != null && resources.getResource() != null
									&& resources.getResource().size() > 0) {
								Resource resource = resources.getResource().get(0);
								UserPayload userPayload = resource.getUserPayload();
								if (userPayload != null) {
									// logger.info("firstName :"+
									// resource.getUserPayload().getFirstName()+"lastName:
									// "+
									// resource.getUserPayload().getLastName());
									List<EmailAddress> emailList = userPayload.getEmails();
									if (emailList != null && emailList.size() > 0) {
										for (EmailAddress emailAddress : emailList) {
											if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
												String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
														.append(ConnectionSettings.getIamForgetuserName())
														.append("password").append("?to=")
														.append(java.net.URLEncoder.encode(
																StringUtils.defaultString(emailAddress.getValue())))
														.append("&username=")
														.append(java.net.URLEncoder
																.encode(StringUtils.defaultString(userId)))
														.append("&").append(AppConstants.OPTUMID_HEADER_TARGETPORTAL)
														.append("=").append(targetPortal).append("&")
														.append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
														.append(targetBrand).append("&")
														.append(AppConstants.OPTUMID_HEADER_LANGUAGE).append("=")
														.append(lang).append("&userid=").append(java.net.URLEncoder
																.encode(StringUtils.defaultString(userId)))
														.toString();
												ConnectionSettings.getRestClient(emailUrl.trim())
														.getAsJson(String.class);
											}
										}

									}
								}
							}
						}
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("200");
						error.setDescription("password id updated");
						return error;

					} else if (StringUtils.containsIgnoreCase(response, "User not found")) {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("User not found");
						return error;
					} else if (StringUtils.containsIgnoreCase(response, "Old password can not be reused")) {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Old password cannot be reused");
						return error;
					} else if (StringUtils.containsIgnoreCase(response, "Error")) {
						ObjectMapper objectMapper = new ObjectMapper();
						JsonNode rootNode;
						rootNode = objectMapper.readTree(response);
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("400");
						error.setDescription(rootNode.get("errors").get("Error").get(0).get("description").textValue());
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "lockUser", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> lockUser(final String userID) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				UserLookupRequest lookupRequest = new UserLookupRequest();
				lookupRequest.setUserid(userID);

				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<UserLookupRequest>(lookupRequest,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamUserLockRes()),
					// HttpMethod.PUT, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamUserLockRes())
							.putJson(lookupRequest, String.class);
					if (response != null && StringUtils.contains(response, "SUCCESS")) {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("200");
						error.setDescription("User account is unlocked");
						return error;

					} else {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Userid not found");
						return error;
					}
				} catch (RestClientException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getChallenges", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> getChallenges() {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {

				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamChallenges()),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamChallenges())
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && user.getStatus() != null
							&& StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resource resource = user.getResource();
						if (resource != null && resource.getChallengeResponseQuestion() != null) {

							return resource.getChallengeResponseQuestion();
						}

					} else {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Resource not found");
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "registerUser", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<AddUserResponse> registerUser(final AddUserRequest addUserRequest) {
		return new AsyncResult<AddUserResponse>() {
			@SuppressWarnings("unchecked")
			@Override
			public AddUserResponse invoke() {

				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<AddUserRequest>(addUserRequest,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				addUserRequest.setUserName(URLEncoder.encode((addUserRequest.getUserName())));
				addUserRequest.setPrimaryEmail(URLEncoder.encode((addUserRequest.getPrimaryEmail())));
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamRegisterUser()),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamRegisterUser())
							.postJson(addUserRequest, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					AddUserResponse addUserResponse = mapper.readValue(response, AddUserResponse.class);
					return addUserResponse;

				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				AddUserResponse addUserResponse2 = new AddUserResponse();
				List<ErrorMessage> errorMessages = new ArrayList<ErrorMessage>();
				ErrorMessage errorMessage = new ErrorMessage();
				errorMessage.setCode("500");
				errorMessage.setDesc("Internal Server Error");
				errorMessages.add(errorMessage);
				addUserResponse2.setStatus("FAILURE");
				addUserResponse2.setErrorMessages(errorMessages);
				return addUserResponse2;
			}

		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "checkUserName", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<CheckUserNameResponse> checkUserName(final String userID) {
		return new AsyncResult<CheckUserNameResponse>() {
			@SuppressWarnings("unchecked")
			@Override
			public CheckUserNameResponse invoke() {
				User user = new User();
				UserName userName = new UserName();
				userName.setValue((URLEncoder.encode(StringUtils.defaultString(userID))));
				userName.setUserAware(false);
				IdentificationData identificationData = new IdentificationData();
				identificationData.setUserName(userName);
				user.setUserIdentificationData(identificationData);

				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity<User>(user,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamCheckUserName()),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamCheckUserName())
							.postJson(user, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response oResponse;
					oResponse = mapper.readValue(response, Response.class);
					if (oResponse != null && oResponse.getStatus() != null
							&& StringUtils.equalsIgnoreCase(oResponse.getStatus().toString(), "SUCCESS")) {
						CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
						checkUserNameResponse.setInfo(oResponse.getInfo());
						checkUserNameResponse.setStatus(StatusEnum.SUCCESS);
						checkUserNameResponse.setSuggestedUsernames(oResponse.getResource().getSuggestedUsernames());
						logger.info("in successful response of checkUserName");
						return checkUserNameResponse;
					} else {
						Errors error = oResponse.getErrors();
						List<com.optum.ogn.iam.model.Error> errorList = error.getError();
						String description = null;
						if (errorList != null && errorList.size() > 0) {
							description = errorList.get(0).getDescription();
						}
						CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
						checkUserNameResponse.setInfo(description);
						checkUserNameResponse.setStatus(StatusEnum.FAILURE);
						logger.info(description);
						return checkUserNameResponse;

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				CheckUserNameResponse checkUserNameResponse = new CheckUserNameResponse();
				checkUserNameResponse.setInfo("Internal Server Exception");
				checkUserNameResponse.setStatus(StatusEnum.FAILURE);
				logger.info("in Internal Server Exception response of checkUserName");
				return checkUserNameResponse;
			}
		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "auditUser", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> auditUser(final UserAudit UserAudit) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				AddIRMAuditLogEventRequest eventRequest = new AddIRMAuditLogEventRequest();
				AuditLogEvent auditLogIRMEvent = new AuditLogEvent();
				auditLogIRMEvent.setUserID((URLEncoder.encode(StringUtils.defaultString(UserAudit.getUserId()))));
				auditLogIRMEvent.setActivity(ActivityEnum.valueOf(UserAudit.getActivity()));
				auditLogIRMEvent.setMessage(UserAudit.getMessage());
				auditLogIRMEvent.setSessionID(UserAudit.getSessionID());
				auditLogIRMEvent.setSourceIPAddr(UserAudit.getSourceIPAddr());
				auditLogIRMEvent.setClientIPAddr(UserAudit.getClientIPAddr());
				auditLogIRMEvent.setLogLevel(LogLevelEnum.INFO);
				eventRequest.setAuditLogIRMEvent(auditLogIRMEvent);
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<AddIRMAuditLogEventRequest>(eventRequest,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				/*
				 * ObjectWriter ow = new
				 * ObjectMapper().writer().withDefaultPrettyPrinter(); try {
				 * String json = ow.writeValueAsString(auditLogIRMEvent);
				 * System.out.println(json);
				 * System.out.println(ow.writeValueAsString(eventRequest)); }
				 * catch (JsonProcessingException e1) { // TODO Auto-generated
				 * catch block e1.printStackTrace(); }
				 */
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamAudit()),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamAudit())
							.postJson(eventRequest, String.class);
					return response;
				} catch (RestClientException e) {
					e.printStackTrace();
				}
				ErrorMessage errorMessage = new ErrorMessage();
				errorMessage.setCode("500");
				errorMessage.setDesc("Internal Server Error");
				return errorMessage;
			}
		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "addAppAccess", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> addAppAccess(final String uuid, final String rpAlias) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				AddApplicationAccessRequest eventRequest = new AddApplicationAccessRequest();
				eventRequest.setUuid((URLEncoder.encode(StringUtils.defaultString(uuid))));
				OnBehalfOf onBehalof = new OnBehalfOf();
				onBehalof.setRpAppAlias(rpAlias);
				eventRequest.setOnBehalfOf(onBehalof);

				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<AddApplicationAccessRequest>(eventRequest,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamAddAppAccess()),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamAddAppAccess())
							.postJson(eventRequest, String.class);
					return response;
				} catch (RestClientException e) {
					e.printStackTrace();
				}
				ErrorMessage errorMessage = new ErrorMessage();
				errorMessage.setCode("500");
				errorMessage.setDesc("Internal Server Error");
				return errorMessage;
			}
		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getUserSQ", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Map<String, Boolean>> getUserSQ(final String userId) {
		return new AsyncResult<Map<String, Boolean>>() {
			@SuppressWarnings("unchecked")
			@Override
			public Map<String, Boolean> invoke() {

				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				Map<String, Boolean> result = new HashMap<String, Boolean>();
				result.put("isEmailAvailable", false);
				result.put("isEmailVerified", false);
				result.put("isPhoneAvailable", false);
				result.put("isPhoneVerified", false);
				result.put("isUserLocked", false);
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					if (response != null && StringUtils.contains(response, "ADMINISTRATIVE_LOCK")) {
						result.remove("isUserLocked");
						result.put("isUserLocked", true);

					}
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								List<EmailAddress> emailList = userPayload.getEmails();
								if (emailList != null && emailList.size() > 0) {
									for (EmailAddress emailAddress : emailList) {

										if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
											result.remove("isEmailAvailable");
											result.put("isEmailAvailable", true);
											result.remove("isEmailVerified");
											result.put("isEmailVerified", emailAddress.getVerified());
										}
									}
								}
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail != null) {
									List<PhoneNumber> phoneList = userDetail.getPhoneNumbers();
									if (phoneList != null && phoneList.size() > 0) {
										for (PhoneNumber phoneNumber : phoneList) {

											if (StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
													"MOBILE")
													|| StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
															"HOME")) {
												result.remove("isPhoneAvailable");
												result.put("isPhoneAvailable", true);
												result.remove("isPhoneVerified");
												result.put("isPhoneVerified", phoneNumber.getVerified());
											}
										}
									}
								}
							}

						}
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return result;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "resetPassword", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> resetPassword(final String email, final String userId) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				PasswordV2Parameters passwordV2Parameters = new PasswordV2Parameters();
				passwordV2Parameters.setUserid((userId));
				Map<String, String> map = new HashMap<String, String>();
				map.put("email", (email));
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<PasswordV2Parameters>(passwordV2Parameters,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;

				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamPasswordRes()+"?resetpassword=true"),
					// HttpMethod.PUT, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(ConnectionSettings.getIamServer()
									+ ConnectionSettings.getIamPasswordRes() + "?resetpassword=true")
							.putJson(passwordV2Parameters, String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {

						UserPayload userPayload = user.getResource().getUserPayload();
						if (userPayload != null) {
							// logger.info("firstName :"+
							// user.getResource().getUserPayload().getFirstName()+"lastName:
							// "+
							// user.getResource().getUserPayload().getLastName());
							map.put("key", (userPayload.getUserDetail().getCredential().getPassword()));
							// request = new HttpEntity<Map>(map,headers);
							String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
									.append(ConnectionSettings.getIamEmailVerf()).append("/reset/password").toString();
							// response = restTemplate.exchange(emailUrl,
							// HttpMethod.POST, request, String.class);
							String plainUserName = user.getResource().getUserIdentificationData().getUserName()
									.getValue();
							user.getResource().getUserIdentificationData().getUserName()
									.setValue(URLEncoder.encode(StringUtils.defaultString(plainUserName)));
							response = ConnectionSettings.getSecureRestClient(emailUrl).postJson(map, String.class);
						}
						logger.info("in resetpassword password id updated");
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("200");
						error.setDescription("password id updated");
						return error;

					} else if (StringUtils.containsIgnoreCase(response, "User not found")) {
						logger.info("in resetpassword User not found");
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("User not found");
						return error;
					} else if (StringUtils.containsIgnoreCase(response, "Old password can not be reused")) {
						logger.info("in resetpassword Old password cannot be reused");
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Old password cannot be reused");
						return error;
					} else if (StringUtils.containsIgnoreCase(response, "Error")) {
						logger.info("in resetpassword 400 error");
						ObjectMapper objectMapper = new ObjectMapper();
						JsonNode rootNode;
						rootNode = objectMapper.readTree(response);
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("400");
						error.setDescription(rootNode.get("errors").get("Error").get(0).get("description").textValue());
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "modifyChallengeQue", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> modifyChallengeQue(final List<ChallengeResponseQuestion> securityQuestionAndAnswers,
			final String userId, final String targetPortal, final String targetBrand, final String lang) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				String newEmail = "";
				// HashMap<String, String> body = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(body,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				try {
					// response = restTemplate.getForEntity(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {
							Resource resource = resources.getResource().get(0);
							if (resource.getUserPayload().getUserDetail().getCredential() == null) {

								Credential credential = new Credential();
								resource.getUserPayload().getUserDetail().setCredential(credential);
							}
							resource.getUserPayload().getUserDetail().getCredential()
									.setSecurityQuestionAndAnswers(securityQuestionAndAnswers);
							List<TypesEnum> typesEnumList = new ArrayList<TypesEnum>();
							typesEnumList.add(TypesEnum.SECURITY_QUESTIONS);
							resource.getUserPayload().getUserDetail().getCredential().setTypes(typesEnumList);
							ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
							List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
							actionTypes.add(ActionTypesEnum.CHALLENGE_RESPONSE_QUESTIONS);
							modificationActionTypeList.setActionTypes(actionTypes);
							resource.setModificationActionTypeList(modificationActionTypeList);
							resource.setResultItems(null);
							resource.setSuggestedUsernames(null);
							resource.setChallengeResponseQuestion(null);
							// headers = new LinkedMultiValueMap<String,
							// String>();
							// headers.add("Accept",
							// MediaType.APPLICATION_JSON.toString());
							mapper.setSerializationInclusion(Include.NON_NULL);
							// request = new
							// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
							// User.class),headers);
							// response = restTemplate.exchange(new
							// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
							// HttpMethod.PUT, request, String.class);
							response = ConnectionSettings
									.getSecureRestClient(ConnectionSettings.getIamServer()
											+ ConnectionSettings.getIamProfileUpdateRes())
									.putJson(mapper.readValue(mapper.writeValueAsString(resource), User.class),
											String.class);
						}
						if (StringUtils.containsIgnoreCase(response, "Error")) {
							ObjectMapper objectMapper = new ObjectMapper();
							JsonNode rootNode;
							rootNode = objectMapper.readTree(response);
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("400");
							error.setDescription(
									rootNode.get("errors").get("Error").get(0).get("description").textValue());
							return error;
						} else {
							if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
									&& user.getInfo() == null) {
								Resources resources1 = user.getResources();
								if (resources1 != null && resources1.getResource() != null
										&& resources1.getResource().size() > 0) {
									Resource resource = resources1.getResource().get(0);
									UserPayload userPayload = resource.getUserPayload();
									if (userPayload != null) {

										List<EmailAddress> emailList = userPayload.getEmails();
										if (emailList != null && emailList.size() > 0) {
											for (EmailAddress emailAddress : emailList) {
												if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
													newEmail = emailAddress.getValue();
												}

											}
										}
									}
								}
							}
							String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
									.append(ConnectionSettings.getIamForgetuserName()).append("security").append("?to=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(newEmail)))
									.append("&username=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId))).append("&")
									.append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
									.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
									.append(targetBrand).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE)
									.append("=").append(lang).append("&userid=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId))).toString();
							ConnectionSettings.getRestClient(emailUrl.trim()).getAsJson(String.class);
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("200");
							error.setDescription("security questions are successfully updated");
							return error;
						}

					} else {
						logger.info("in update SQ method userid not found");
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Userid not found");
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				logger.info("in update SQ method Internal server exception");
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "searchUsers", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Response> searchUsers(final Map<String, String> filterMap) {
		return new AsyncResult<Response>() {
			@SuppressWarnings("unchecked")
			@Override
			public Response invoke() {
				logger.info("in searchUsers method");
				String emailString = (filterMap.get("email"));
				String firstNameString = filterMap.get("firstName");
				String lastNameString = filterMap.get("lastName");
				String dateOfBirth = filterMap.get("dateOfBirth");
				String phone = filterMap.get("phone");
				Filter filter = null;

				SearchArguments searchArguments = new SearchArguments();
				ArrayList<Filter> filterList = new ArrayList<Filter>();

				if (emailString != null) {

					filter = new Filter();
					filter.setKey("emails");
					filter.setValue(filterMap.get("email"));
					filterList.add(filter);
				}

				if (firstNameString != null) {

					filter = new Filter();
					filter.setKey("firstName");
					filter.setValue(filterMap.get("firstName"));
					filterList.add(filter);
				}

				if (lastNameString != null) {

					filter = new Filter();
					filter.setKey("lastName");
					filter.setValue(filterMap.get("lastName"));
					filterList.add(filter);
				}
				if (dateOfBirth != null) {

					filter = new Filter();
					filter.setKey("dateOfBirth");
					filter.setValue(filterMap.get("dateOfBirth"));
					filterList.add(filter);
				}
				if (phone != null) {
					Filter filter1 = new Filter();
					filter1.setKey("phoneNumbers.areaCode");
					filter1.setValue(phone.substring(0, 3));
					filterList.add(filter1);

					Filter filter2 = new Filter();
					filter2.setKey("phoneNumbers.number");
					filter2.setValue(phone.substring(3, 10));
					filterList.add(filter2);

					Filter filter3 = new Filter();
					filter3.setKey("phoneNumbers.label");
					filter3.setValue("MOBILE");
					filterList.add(filter3);

					Filter filter4 = new Filter();
					filter4.setKey("phoneNumbers.countryCode");
					filter4.setValue("1");
					filterList.add(filter4);
				}

				searchArguments.setFilter(filterList);
				SearchParameters parameters = new SearchParameters();
				parameters.setSearcharguments(searchArguments);
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new
				// HttpEntity<SearchParameters>(parameters,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				Response response = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByEmailRes()),
					// HttpMethod.POST, request, String.class);
					String content = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByEmailRes())
							.postJson(parameters, String.class);

					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(content, Response.class);
					return user;

				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return response;
			}
		};
	}
	/*
	 * public static void main(String...strings){
	 * 
	 * AddIRMAuditLogEventRequest addIRMAuditLogEventRequest = new
	 * AddIRMAuditLogEventRequest(); AuditLogEvent auditLogEvent = new
	 * AuditLogEvent(); auditLogEvent.setUserID("jdlkdjfs");
	 * auditLogEvent.setActivity(ActivityEnum.ADD_USER_EMAIL);
	 * auditLogEvent.setSessionID("sdfsd"); auditLogEvent.setMessage("sdfa");
	 * auditLogEvent.setLogLevel(LogLevelEnum.ERROR);
	 * auditLogEvent.setClientIPAddr("doee");
	 * addIRMAuditLogEventRequest.setAuditLogIRMEvent(auditLogEvent);
	 * ObjectMapper objectMapper = new ObjectMapper(); try {
	 * System.out.println(objectMapper.writeValueAsString(
	 * addIRMAuditLogEventRequest)); } catch (JsonProcessingException e) { //
	 * TODO Auto-generated catch block e.printStackTrace(); } }
	 */

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getProfileInfo", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Map<String, String>> getProfileInfo(final String userId, final String phoneType) {
		return new AsyncResult<Map<String, String>>() {
			@SuppressWarnings("unchecked")
			@Override
			public Map<String, String> invoke() {
				logger.info("in getProfileInfo");

				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				Map<String, String> result = new HashMap<String, String>();
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								// logger.info("firstName :"+
								// resource.getUserPayload().getFirstName()+"lastName:
								// "+ resource.getUserPayload().getLastName());
								List<EmailAddress> emailList = userPayload.getEmails();
								if (emailList != null && emailList.size() > 0) {
									for (EmailAddress emailAddress : emailList) {

										if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
											result.put("email", emailAddress.getValue());
										}
									}
								}
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail != null) {
									List<PhoneNumber> phoneList = userDetail.getPhoneNumbers();
									if (phoneList != null && phoneList.size() > 0) {
										for (PhoneNumber phoneNumber : phoneList) {

											if (StringUtils.equalsIgnoreCase(phoneNumber.getLabel().toString(),
													phoneType)) {
												result.put("phone",
														phoneNumber.getAreaCode() + phoneNumber.getNumber());
											}
										}
									}
								}
							}

						}
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return result;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getUserQuetionaire", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Map<String, String>> getUserQuetionaire(final String userId) {
		return new AsyncResult<Map<String, String>>() {
			@SuppressWarnings("unchecked")
			@Override
			public Map<String, String> invoke() {
				logger.info("in getUserQuetionaire");
				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				Map<String, String> result = new HashMap<String, String>();
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail.getCredential() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {

									List<ChallengeResponseQuestion> challengeResponseQuestions = userDetail
											.getCredential().getSecurityQuestionAndAnswers();
									for (ChallengeResponseQuestion challengeResponseQuestion : challengeResponseQuestions) {
										result.put(challengeResponseQuestion.getId(),
												challengeResponseQuestion.getQuestion());
									}
								}

							}
						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return result;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "validateUserQuestionaire", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Map<String, String>> validateUserQuestionaire(final Map<String, String> questionaire,
			final String userId) {
		return new AsyncResult<Map<String, String>>() {
			@SuppressWarnings("unchecked")
			@Override
			public Map<String, String> invoke() {
				Map<String, String> error = new HashMap<String, String>();
				if (questionaire == null || questionaire.isEmpty()) {
					error.put("code", "400");
					error.put("description", "User Security Answers are empty");
					return error;
				}
				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {

								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail.getCredential() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {

									List<ChallengeResponseQuestion> challengeResponseQuestions = userDetail
											.getCredential().getSecurityQuestionAndAnswers();
									for (ChallengeResponseQuestion challengeResponseQuestion : challengeResponseQuestions) {
										if (StringUtils.equalsIgnoreCase(
												questionaire.get(challengeResponseQuestion.getId()),
												challengeResponseQuestion.getAnswer())
												|| StringUtils.equalsIgnoreCase(
														questionaire.get(challengeResponseQuestion.getQuestion()),
														challengeResponseQuestion.getAnswer())) {
											questionaire.remove(challengeResponseQuestion.getQuestion());
											questionaire.remove(challengeResponseQuestion.getId());
										}
									}
								}

							}
						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				if (questionaire.size() == 0) {
					logger.info("in SQ Validation, Successful");
					error.put("code", "200");
					error.put("description", "User Security Answers are Correct");
					return error;
				} else {
					logger.info("in SQ Validation, failure");
					error.put("code", "400");
					error.put("description", "User Security Answers are Wrong");
					/*
					 * for (Map.Entry<String, String> entry :
					 * questionaire.entrySet()) {
					 * error.put(entry.getKey(),entry.getValue()+" is wrong"); }
					 */
					return error;

				}
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getUserInfo", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Response> getUserFiltereList(final String userId) {
		return new AsyncResult<Response>() {
			@SuppressWarnings("unchecked")
			@Override
			public Response invoke() {
				logger.info("in getUserFiltereList resulting in no SQ userlist");

				// HashMap<String, String> payLoad = new HashMap<>();
				// MultiValueMap<String, String> headers = new
				// LinkedMultiValueMap<String, String>();
				// headers.add("Accept", MediaType.APPLICATION_JSON.toString());
				// HttpEntity request = new HttpEntity(payLoad,headers);
				// RestTemplate restTemplate = new RestTemplate();
				// ResponseEntity<String> response = null;
				String response = null;
				Response user = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								// logger.info("firstName :"+
								// resource.getUserPayload().getFirstName()+"lastName:
								// "+ resource.getUserPayload().getLastName());
								UserDetail userDetail = userPayload.getUserDetail();
								userPayload.setUserType(null);
								userPayload.setDateOfBirth(null);
								userPayload.setFirstName(null);
								userPayload.setLastName(null);
								userPayload.setGender(null);
								if (userDetail != null) {
									userDetail.setAddresses(null);
									userDetail.setCredential(null);
									userDetail.setUserAccountStatus(null);
									userDetail.setAttributes(null);
								}
								if (userDetail.getCredential() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {

									List<ChallengeResponseQuestion> challengeResponseQuestions = userDetail
											.getCredential().getSecurityQuestionAndAnswers();
									challengeResponseQuestions.clear();
								}

							}
						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return user;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "deleteUserPhone", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> deleteUserPhone(final String userID) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				String response = null;
				try {
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userID)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {
							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail != null) {
									List<PhoneNumber> phoneList = userDetail.getPhoneNumbers();
									if (phoneList != null && phoneList.size() > 0) {
										for (PhoneNumber phoneNumber : phoneList) {

											if (phoneNumber.getLabel().equals(LabelEnum.MOBILE)) {
												phoneNumber.setAttributeActionType(
														com.optum.ogn.iam.model.PhoneNumber.AttributeActionTypeEnum.DELETE);
												ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
												List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
												actionTypes.add(ActionTypesEnum.PHONES);
												modificationActionTypeList.setActionTypes(actionTypes);
												resource.setModificationActionTypeList(modificationActionTypeList);
												resource.setResultItems(null);
												resource.setSuggestedUsernames(null);
												mapper.setSerializationInclusion(Include.NON_NULL);
												response = ConnectionSettings
														.getSecureRestClient(ConnectionSettings.getIamServer()
																+ ConnectionSettings.getIamProfileUpdateRes())
														.putJson(mapper.readValue(mapper.writeValueAsString(resource),
																User.class), String.class);
											}
										}
									}

								}

							}
						}
					}
					if (StringUtils.containsIgnoreCase(response, "SUCCESS")) {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("200");
						error.setDescription("User Phone is deleted");
						return error;
					} else {
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("400");
						error.setDescription("Phone or UserID not found");
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "addUserDevice", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<AddDeviceResponse> addUserDevice(final Device device) {
		return new AsyncResult<AddDeviceResponse>() {
			@SuppressWarnings("unchecked")
			@Override
			public AddDeviceResponse invoke() {
				try {
					String plainUserName = device.getUserName();
					device.setUserName(URLEncoder.encode(StringUtils.defaultString(plainUserName)));
					return ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamUserDevice())
							.postJson(device, AddDeviceResponse.class);
				} catch (RestClientException e) {
					e.printStackTrace();
				}
				return null;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getUUIDByUserId", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<String> getUUIDByUserId(final String userId) {
		return new AsyncResult<String>() {
			@SuppressWarnings("unchecked")
			@Override
			public String invoke() {
				logger.info("in getUUIDByUserId");

				String uuid = null;
				String response = null;
				Response user = null;
				try {

					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					user = mapper.readValue(response, Response.class);

					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							IdentificationData identificationData = resource.getUserIdentificationData();

							if (identificationData != null && identificationData.getUUID() != null) {

								uuid = identificationData.getUUID().getValue();

							}

						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return uuid;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getUseridByUUID", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<String> getUseridByUUID(final String uuid) {
		return new AsyncResult<String>() {
			@SuppressWarnings("unchecked")
			@Override
			public String invoke() {
				logger.info("in getUUIDByUserId");

				String userid = null;
				String response = null;
				Response user = null;
				try {

					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(uuid)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					user = mapper.readValue(response, Response.class);

					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							IdentificationData identificationData = resource.getUserIdentificationData();

							if (identificationData != null && identificationData.getUserName() != null) {

								userid = identificationData.getUserName().getValue();

							}

						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return userid;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getEmailIDfromUserID", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<String> getEmailIDfromUserID(final String userId) {
		return new AsyncResult<String>() {
			@SuppressWarnings("unchecked")
			@Override
			public String invoke() {
				String email = null;
				String response = null;
				try {
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {
							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								List<EmailAddress> emailList = userPayload.getEmails();
								if (emailList != null && emailList.size() > 0) {
									for (EmailAddress emailAddress : emailList) {
										if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
											email = emailAddress.getValue();
										}
									}
								}
							}
						}
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return email;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getAdminUserList", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Response> getAdminUserList(final String userId) {
		return new AdminUserInfo(userId);
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getSecureUserList", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<String> getSecureUserList(final String userId) {
		return new AsyncResult<String>() {
			@SuppressWarnings("unchecked")
			@Override
			public String invoke() {
				logger.info("in getSecureUserList resulting in secure response");

				String response = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
				} catch (RestClientException e) {
					e.printStackTrace();
				}
				return response;
			}
		};
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "unlockRBAUser", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<String> unlockRBAUser(final AddUserRequest addUserRequest) {
		return new AsyncResult<String>() {
			@SuppressWarnings("unchecked")
			@Override
			public String invoke() {

				String response = null;

				try {
					addUserRequest
							.setUserName(URLEncoder.encode(StringUtils.defaultString(addUserRequest.getUserName())));
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamRegisterUser()),
					// HttpMethod.POST, request, String.class);
					response = ConnectionSettings
							.getRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getRBAUnLock())
							.postJson(addUserRequest, String.class);
					return response;

				} catch (RestClientException e) {
					e.printStackTrace();
				}
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
				return response;
			}

		};

	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "getAdminUserList", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Response> isUserLocked(final String userId) {
		return new AsyncResult<Response>() {
			@SuppressWarnings("unchecked")
			@Override
			public Response invoke() {
				logger.info("in getUserFiltereList resulting in no SQ userlist");
				String response = null;
				Response user = null;
				try {
					// response = restTemplate.exchange(new
					// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileByIdRes()+userId),
					// HttpMethod.GET, request, String.class);
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					response = StringUtils.replace(response, "\"\"", userId);
					user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {

							Resource resource = resources.getResource().get(0);
							UserPayload userPayload = resource.getUserPayload();
							if (userPayload != null) {
								logger.info("firstName :" + resource.getUserPayload().getFirstName() + "lastName: "
										+ resource.getUserPayload().getLastName());
								UserDetail userDetail = userPayload.getUserDetail();
								if (userDetail.getCredential() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers() != null
										&& userDetail.getCredential().getSecurityQuestionAndAnswers().size() > 0) {

									List<ChallengeResponseQuestion> challengeResponseQuestions = userDetail
											.getCredential().getSecurityQuestionAndAnswers();
									challengeResponseQuestions.clear();
								}

							}
						}

					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				return user;
			}
		};
	}

	public Map<String, Boolean> getLockStatus(final String userId) {
		Map<String, Boolean> userProfileMap = new HashMap<String, Boolean>();
		String response = null;
		Response user = null;
		try {
			response = ConnectionSettings
					.getSecureRestClient(ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
							+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
					.getAsJson(String.class);
			ObjectMapper mapper = new ObjectMapper();
			mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			response = StringUtils.replace(response, "\"\"", userId);
			user = mapper.readValue(response, Response.class);
			if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
					&& user.getInfo() == null) {
				Resources resources = user.getResources();
				if (resources != null && resources.getResource() != null && resources.getResource().size() > 0) {

					Resource resource = resources.getResource().get(0);
					UserPayload userPayload = resource.getUserPayload();
					if (userPayload != null) {
						logger.info("firstName :" + resource.getUserPayload().getFirstName() + "lastName: "
								+ resource.getUserPayload().getLastName());
						UserDetail userDetail = userPayload.getUserDetail();
						if (userDetail.getUserAccountStatus() != null) {

							userProfileMap
									.put("LDAP",
											PasswordStatusEnum.ACTIVE
													.equals(userDetail.getUserAccountStatus().getPasswordStatus())
															? false : true);
							userProfileMap
									.put("RSA",
											StringUtils.equalsIgnoreCase(
													userDetail.getUserAccountStatus().getAaStatus(), "VERIFIED") ? false
															: true);
						}

					}
				}

			}
		} catch (RestClientException | IOException e) {
			e.printStackTrace();
		}
		return userProfileMap;
	}

	@HystrixCommand(groupKey = "HealthSafeIdService", commandKey = "setPassword", commandProperties = {
			@HystrixProperty(name = "execution.isolation.thread.timeoutInMilliseconds", value = "60000"),
			@HystrixProperty(name = "circuitBreaker.requestVolumeThreshold", value = "4"),
			@HystrixProperty(name = "circuitBreaker.sleepWindowInMilliseconds", value = "60000"),
			@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") }, threadPoolProperties = {
					@HystrixProperty(name = "coreSize", value = "150"),
					@HystrixProperty(name = "metrics.rollingStats.timeInMilliseconds", value = "180000") })
	public Future<Object> updateName(final String userProfile, final Map<String, String> payLoad, final String userId,
			final String targetPortal, final String targetBrand, final String lang) {
		return new AsyncResult<Object>() {
			@SuppressWarnings("unchecked")
			@Override
			public Object invoke() {
				String newEmail = "";
				String response = null;
				try {
					response = ConnectionSettings
							.getSecureRestClient(
									ConnectionSettings.getIamServer() + ConnectionSettings.getIamProfileByIdRes()
											+ java.net.URLEncoder.encode(StringUtils.defaultString(userId)))
							.getAsJson(String.class);
					ObjectMapper mapper = new ObjectMapper();
					mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);
					mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
					Response user = mapper.readValue(response, Response.class);
					if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
							&& user.getInfo() == null) {
						Resources resources = user.getResources();
						if (resources != null && resources.getResource() != null
								&& resources.getResource().size() > 0) {
							Resource resource = resources.getResource().get(0);
							if (payLoad != null && StringUtils.isNotBlank(payLoad.get("firstName")))
								resource.getUserPayload().setFirstName(payLoad.get("firstName"));
							if (payLoad != null && StringUtils.isNotBlank(payLoad.get("lastName")))
								resource.getUserPayload().setFirstName(payLoad.get("lastName"));
							ModificationActionTypeList modificationActionTypeList = new ModificationActionTypeList();
							List<ActionTypesEnum> actionTypes = new ArrayList<ModificationActionTypeList.ActionTypesEnum>();
							if (payLoad != null && StringUtils.isNotBlank(payLoad.get("firstName")))
								actionTypes.add(ActionTypesEnum.FIRST_NAME);
							if (payLoad != null && StringUtils.isNotBlank(payLoad.get("lastName")))
								actionTypes.add(ActionTypesEnum.LAST_NAME);
							modificationActionTypeList.setActionTypes(actionTypes);
							resource.setModificationActionTypeList(modificationActionTypeList);
							resource.setResultItems(null);
							resource.setSuggestedUsernames(null);
							resource.setChallengeResponseQuestion(null);
							// headers = new LinkedMultiValueMap<String,
							// String>();
							// headers.add("Accept",
							// MediaType.APPLICATION_JSON.toString());
							mapper.setSerializationInclusion(Include.NON_NULL);
							// request = new
							// HttpEntity<User>(mapper.readValue(mapper.writeValueAsString(resource),
							// User.class),headers);
							// response = restTemplate.exchange(new
							// URI(ConnectionSettings.getIamServer()+ConnectionSettings.getIamProfileUpdateRes()),
							// HttpMethod.PUT, request, String.class);
							response = ConnectionSettings
									.getSecureRestClient(ConnectionSettings.getIamServer()
											+ ConnectionSettings.getIamProfileUpdateRes())
									.putJson(mapper.readValue(mapper.writeValueAsString(resource), User.class),
											String.class);
						}
						if (StringUtils.containsIgnoreCase(response, "Error")) {
							ObjectMapper objectMapper = new ObjectMapper();
							JsonNode rootNode;
							rootNode = objectMapper.readTree(response);
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("400");
							error.setDescription(
									rootNode.get("errors").get("Error").get(0).get("description").textValue());
							return error;
						} else {
							if (user != null && StringUtils.equalsIgnoreCase(user.getStatus().toString(), "SUCCESS")
									&& user.getInfo() == null) {
								Resources resources1 = user.getResources();
								if (resources1 != null && resources1.getResource() != null
										&& resources1.getResource().size() > 0) {
									Resource resource = resources1.getResource().get(0);
									UserPayload userPayload = resource.getUserPayload();
									if (userPayload != null) {

										List<EmailAddress> emailList = userPayload.getEmails();
										if (emailList != null && emailList.size() > 0) {
											for (EmailAddress emailAddress : emailList) {
												if (StringUtils.equalsIgnoreCase(emailAddress.getLabel(), "Primary")) {
													newEmail = emailAddress.getValue();
												}

											}
										}
									}
								}
							}
							String emailUrl = new StringBuilder(ConnectionSettings.getIamServer())
									.append(ConnectionSettings.getIamForgetuserName()).append("security").append("?to=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(newEmail)))
									.append("&username=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId))).append("&")
									.append(AppConstants.OPTUMID_HEADER_TARGETPORTAL).append("=").append(targetPortal)
									.append("&").append(AppConstants.OPTUMID_HEADER_BRANDPORTAL).append("=")
									.append(targetBrand).append("&").append(AppConstants.OPTUMID_HEADER_LANGUAGE)
									.append("=").append(lang).append("&userid=")
									.append(java.net.URLEncoder.encode(StringUtils.defaultString(userId))).toString();
							ConnectionSettings.getRestClient(emailUrl.trim()).getAsJson(String.class);
							com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
							error.setCode("200");
							error.setDescription("name is updated");
							return error;
						}

					} else {
						logger.info("in update name method userid not found");
						com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
						error.setCode("404");
						error.setDescription("Userid not found");
						return error;
					}
				} catch (RestClientException | IOException e) {
					e.printStackTrace();
				}
				logger.info("in update name method Internal server exception");
				com.optum.ogn.iam.model.Error error = new com.optum.ogn.iam.model.Error();
				error.setCode("500");
				error.setDescription("Internal Server Exception");
				return error;
			}

		};
	}

}
