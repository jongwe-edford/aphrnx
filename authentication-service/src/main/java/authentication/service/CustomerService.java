package security.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import security.auth.exception.PhoneNumberAlreadyInUseException;
import security.auth.exception.VendorAlreadyExistsException;
import security.auth.exception.VendorNotFoundException;
import security.auth.model.Customer;
import security.auth.payload.request.CustomerRegistrationRequest;
import security.auth.payload.request.CustomerUpdateRequest;


public interface CustomerService {
    Customer saveCustomer(CustomerRegistrationRequest registrationRequest, HttpServletRequest servletRequest) throws VendorAlreadyExistsException, PhoneNumberAlreadyInUseException, PhoneNumberAlreadyInUseException;

    Customer retrieveCustomer() throws VendorNotFoundException;

    Customer updateCustomerInfo(CustomerUpdateRequest updateRequest) throws VendorNotFoundException;
}
