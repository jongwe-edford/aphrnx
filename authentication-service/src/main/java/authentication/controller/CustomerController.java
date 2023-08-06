/*
 * Copyright (c) 2022. No party of this code may be reused without permision from the author Edford Jongwe or from Aphrnx LLC,
 */

package security.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import security.auth.exception.PhoneNumberAlreadyInUseException;
import security.auth.exception.VendorAlreadyExistsException;
import security.auth.exception.VendorNotFoundException;
import security.auth.model.Customer;
import security.auth.payload.request.CustomerRegistrationRequest;
import security.auth.payload.request.CustomerUpdateRequest;
import security.auth.payload.response.Response;
import security.auth.service.CustomerService;


@RestController
@RequestMapping(path = "customer")
@AllArgsConstructor
public class CustomerController {

    private final CustomerService customerService;


    @PostMapping(path = "create")
    public ResponseEntity<Customer> saveCustomer(@RequestBody CustomerRegistrationRequest customerRegistrationRequest,
                                                 HttpServletRequest httpServletRequest) throws VendorAlreadyExistsException, PhoneNumberAlreadyInUseException {
        return new ResponseEntity<>(customerService.saveCustomer(customerRegistrationRequest, httpServletRequest), HttpStatus.OK);
    }

    @GetMapping()
    public ResponseEntity<Customer> retrieveCustomer() throws VendorNotFoundException {
        return new ResponseEntity<>(customerService.retrieveCustomer(), HttpStatus.OK);
    }

    @PatchMapping(path = "update")
    public ResponseEntity<Customer> updateCustomerInfo(@RequestBody CustomerUpdateRequest customerUpdateRequest) throws VendorNotFoundException {
        return new ResponseEntity<>(customerService.updateCustomerInfo(customerUpdateRequest), HttpStatus.CREATED);
    }

}
