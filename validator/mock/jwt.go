// generated by "charlatan -output=jwt.go JWT".  DO NOT EDIT.
package validatorMock

import (
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
	"reflect"
)

// JWTClaimsInvocation represents a single call of FakeJWT.Claims
type JWTClaimsInvocation struct {
	Results struct {
		Ident1 jwt.Claims
	}
}

// JWTValidateInvocation represents a single call of FakeJWT.Validate
type JWTValidateInvocation struct {
	Parameters struct {
		Key    interface{}
		Method crypto.SigningMethod
		V      []*jwt.Validator
	}
	Results struct {
		Ident1 error
	}
}

// NewJWTValidateInvocation creates a new instance of JWTValidateInvocation
func NewJWTValidateInvocation(key interface{}, method crypto.SigningMethod, v []*jwt.Validator, ident1 error) *JWTValidateInvocation {
	invocation := new(JWTValidateInvocation)

	invocation.Parameters.Key = key
	invocation.Parameters.Method = method
	invocation.Parameters.V = v

	invocation.Results.Ident1 = ident1

	return invocation
}

// JWTSerializeInvocation represents a single call of FakeJWT.Serialize
type JWTSerializeInvocation struct {
	Parameters struct {
		Key interface{}
	}
	Results struct {
		Ident1 []byte
		Ident2 error
	}
}

// NewJWTSerializeInvocation creates a new instance of JWTSerializeInvocation
func NewJWTSerializeInvocation(key interface{}, ident1 []byte, ident2 error) *JWTSerializeInvocation {
	invocation := new(JWTSerializeInvocation)

	invocation.Parameters.Key = key

	invocation.Results.Ident1 = ident1
	invocation.Results.Ident2 = ident2

	return invocation
}

// JWTTestingT represents the methods of "testing".T used by charlatan Fakes.  It avoids importing the testing package.
type JWTTestingT interface {
	Error(...interface{})
	Errorf(string, ...interface{})
	Fatal(...interface{})
	Helper()
}

/*
FakeJWT is a mock implementation of JWT for testing.
Use it in your tests as in this example:

	package example

	func TestWithJWT(t *testing.T) {
		f := &aaa.FakeJWT{
			ClaimsHook: func() (ident1 jwt.Claims) {
				// ensure parameters meet expectations, signal errors using t, etc
				return
			},
		}

		// test code goes here ...

		// assert state of FakeClaims ...
		f.AssertClaimsCalledOnce(t)
	}

Create anonymous function implementations for only those interface methods that
should be called in the code under test.  This will force a panic if any
unexpected calls are made to FakeClaims.
*/
type FakeJWT struct {
	ClaimsHook    func() jwt.Claims
	ValidateHook  func(interface{}, crypto.SigningMethod, ...*jwt.Validator) error
	SerializeHook func(interface{}) ([]byte, error)

	ClaimsCalls    []*JWTClaimsInvocation
	ValidateCalls  []*JWTValidateInvocation
	SerializeCalls []*JWTSerializeInvocation
}

// NewFakeJWTDefaultPanic returns an instance of FakeJWT with all hooks configured to panic
func NewFakeJWTDefaultPanic() *FakeJWT {
	return &FakeJWT{
		ClaimsHook: func() (ident1 jwt.Claims) {
			panic("Unexpected call to JWT.Claims")
		},
		ValidateHook: func(interface{}, crypto.SigningMethod, ...*jwt.Validator) (ident1 error) {
			panic("Unexpected call to JWT.Validate")
		},
		SerializeHook: func(interface{}) (ident1 []byte, ident2 error) {
			panic("Unexpected call to JWT.Serialize")
		},
	}
}

// NewFakeJWTDefaultFatal returns an instance of FakeJWT with all hooks configured to call t.Fatal
func NewFakeJWTDefaultFatal(t_sym1 JWTTestingT) *FakeJWT {
	return &FakeJWT{
		ClaimsHook: func() (ident1 jwt.Claims) {
			t_sym1.Fatal("Unexpected call to JWT.Claims")
			return
		},
		ValidateHook: func(interface{}, crypto.SigningMethod, ...*jwt.Validator) (ident1 error) {
			t_sym1.Fatal("Unexpected call to JWT.Validate")
			return
		},
		SerializeHook: func(interface{}) (ident1 []byte, ident2 error) {
			t_sym1.Fatal("Unexpected call to JWT.Serialize")
			return
		},
	}
}

// NewFakeJWTDefaultError returns an instance of FakeJWT with all hooks configured to call t.Error
func NewFakeJWTDefaultError(t_sym2 JWTTestingT) *FakeJWT {
	return &FakeJWT{
		ClaimsHook: func() (ident1 jwt.Claims) {
			t_sym2.Error("Unexpected call to JWT.Claims")
			return
		},
		ValidateHook: func(interface{}, crypto.SigningMethod, ...*jwt.Validator) (ident1 error) {
			t_sym2.Error("Unexpected call to JWT.Validate")
			return
		},
		SerializeHook: func(interface{}) (ident1 []byte, ident2 error) {
			t_sym2.Error("Unexpected call to JWT.Serialize")
			return
		},
	}
}

func (f *FakeJWT) Reset() {
	f.ClaimsCalls = []*JWTClaimsInvocation{}
	f.ValidateCalls = []*JWTValidateInvocation{}
	f.SerializeCalls = []*JWTSerializeInvocation{}
}

func (f_sym3 *FakeJWT) Claims() (ident1 jwt.Claims) {
	if f_sym3.ClaimsHook == nil {
		panic("JWT.Claims() called but FakeJWT.ClaimsHook is nil")
	}

	invocation_sym3 := new(JWTClaimsInvocation)
	f_sym3.ClaimsCalls = append(f_sym3.ClaimsCalls, invocation_sym3)

	ident1 = f_sym3.ClaimsHook()

	invocation_sym3.Results.Ident1 = ident1

	return
}

// SetClaimsStub configures JWT.Claims to always return the given values
func (f_sym4 *FakeJWT) SetClaimsStub(ident1 jwt.Claims) {
	f_sym4.ClaimsHook = func() jwt.Claims {
		return ident1
	}
}

// ClaimsCalled returns true if FakeJWT.Claims was called
func (f *FakeJWT) ClaimsCalled() bool {
	return len(f.ClaimsCalls) != 0
}

// AssertClaimsCalled calls t.Error if FakeJWT.Claims was not called
func (f *FakeJWT) AssertClaimsCalled(t JWTTestingT) {
	t.Helper()
	if len(f.ClaimsCalls) == 0 {
		t.Error("FakeJWT.Claims not called, expected at least one")
	}
}

// ClaimsNotCalled returns true if FakeJWT.Claims was not called
func (f *FakeJWT) ClaimsNotCalled() bool {
	return len(f.ClaimsCalls) == 0
}

// AssertClaimsNotCalled calls t.Error if FakeJWT.Claims was called
func (f *FakeJWT) AssertClaimsNotCalled(t JWTTestingT) {
	t.Helper()
	if len(f.ClaimsCalls) != 0 {
		t.Error("FakeJWT.Claims called, expected none")
	}
}

// ClaimsCalledOnce returns true if FakeJWT.Claims was called exactly once
func (f *FakeJWT) ClaimsCalledOnce() bool {
	return len(f.ClaimsCalls) == 1
}

// AssertClaimsCalledOnce calls t.Error if FakeJWT.Claims was not called exactly once
func (f *FakeJWT) AssertClaimsCalledOnce(t JWTTestingT) {
	t.Helper()
	if len(f.ClaimsCalls) != 1 {
		t.Errorf("FakeJWT.Claims called %d times, expected 1", len(f.ClaimsCalls))
	}
}

// ClaimsCalledN returns true if FakeJWT.Claims was called at least n times
func (f *FakeJWT) ClaimsCalledN(n int) bool {
	return len(f.ClaimsCalls) >= n
}

// AssertClaimsCalledN calls t.Error if FakeJWT.Claims was called less than n times
func (f *FakeJWT) AssertClaimsCalledN(t JWTTestingT, n int) {
	t.Helper()
	if len(f.ClaimsCalls) < n {
		t.Errorf("FakeJWT.Claims called %d times, expected >= %d", len(f.ClaimsCalls), n)
	}
}

func (f_sym5 *FakeJWT) Validate(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) (ident1 error) {
	if f_sym5.ValidateHook == nil {
		panic("JWT.Validate() called but FakeJWT.ValidateHook is nil")
	}

	invocation_sym5 := new(JWTValidateInvocation)
	f_sym5.ValidateCalls = append(f_sym5.ValidateCalls, invocation_sym5)

	invocation_sym5.Parameters.Key = key
	invocation_sym5.Parameters.Method = method
	invocation_sym5.Parameters.V = v

	ident1 = f_sym5.ValidateHook(key, method, v...)

	invocation_sym5.Results.Ident1 = ident1

	return
}

// SetValidateStub configures JWT.Validate to always return the given values
func (f_sym6 *FakeJWT) SetValidateStub(ident1 error) {
	f_sym6.ValidateHook = func(interface{}, crypto.SigningMethod, ...*jwt.Validator) error {
		return ident1
	}
}

// SetValidateInvocation configures JWT.Validate to return the given results when called with the given parameters
// If no match is found for an invocation the result(s) of the fallback function are returned
func (f_sym7 *FakeJWT) SetValidateInvocation(calls_sym7 []*JWTValidateInvocation, fallback_sym7 func() error) {
	f_sym7.ValidateHook = func(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) (ident1 error) {
		for _, call_sym7 := range calls_sym7 {
			if reflect.DeepEqual(call_sym7.Parameters.Key, key) && reflect.DeepEqual(call_sym7.Parameters.Method, method) && reflect.DeepEqual(call_sym7.Parameters.V, v) {
				ident1 = call_sym7.Results.Ident1

				return
			}
		}

		return fallback_sym7()
	}
}

// ValidateCalled returns true if FakeJWT.Validate was called
func (f *FakeJWT) ValidateCalled() bool {
	return len(f.ValidateCalls) != 0
}

// AssertValidateCalled calls t.Error if FakeJWT.Validate was not called
func (f *FakeJWT) AssertValidateCalled(t JWTTestingT) {
	t.Helper()
	if len(f.ValidateCalls) == 0 {
		t.Error("FakeJWT.Validate not called, expected at least one")
	}
}

// ValidateNotCalled returns true if FakeJWT.Validate was not called
func (f *FakeJWT) ValidateNotCalled() bool {
	return len(f.ValidateCalls) == 0
}

// AssertValidateNotCalled calls t.Error if FakeJWT.Validate was called
func (f *FakeJWT) AssertValidateNotCalled(t JWTTestingT) {
	t.Helper()
	if len(f.ValidateCalls) != 0 {
		t.Error("FakeJWT.Validate called, expected none")
	}
}

// ValidateCalledOnce returns true if FakeJWT.Validate was called exactly once
func (f *FakeJWT) ValidateCalledOnce() bool {
	return len(f.ValidateCalls) == 1
}

// AssertValidateCalledOnce calls t.Error if FakeJWT.Validate was not called exactly once
func (f *FakeJWT) AssertValidateCalledOnce(t JWTTestingT) {
	t.Helper()
	if len(f.ValidateCalls) != 1 {
		t.Errorf("FakeJWT.Validate called %d times, expected 1", len(f.ValidateCalls))
	}
}

// ValidateCalledN returns true if FakeJWT.Validate was called at least n times
func (f *FakeJWT) ValidateCalledN(n int) bool {
	return len(f.ValidateCalls) >= n
}

// AssertValidateCalledN calls t.Error if FakeJWT.Validate was called less than n times
func (f *FakeJWT) AssertValidateCalledN(t JWTTestingT, n int) {
	t.Helper()
	if len(f.ValidateCalls) < n {
		t.Errorf("FakeJWT.Validate called %d times, expected >= %d", len(f.ValidateCalls), n)
	}
}

// ValidateCalledWith returns true if FakeJWT.Validate was called with the given values
func (f_sym8 *FakeJWT) ValidateCalledWith(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) bool {
	for _, call_sym8 := range f_sym8.ValidateCalls {
		if reflect.DeepEqual(call_sym8.Parameters.Key, key) && reflect.DeepEqual(call_sym8.Parameters.Method, method) && reflect.DeepEqual(call_sym8.Parameters.V, v) {
			return true
		}
	}

	return false
}

// AssertValidateCalledWith calls t.Error if FakeJWT.Validate was not called with the given values
func (f_sym9 *FakeJWT) AssertValidateCalledWith(t JWTTestingT, key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) {
	t.Helper()
	var found_sym9 bool
	for _, call_sym9 := range f_sym9.ValidateCalls {
		if reflect.DeepEqual(call_sym9.Parameters.Key, key) && reflect.DeepEqual(call_sym9.Parameters.Method, method) && reflect.DeepEqual(call_sym9.Parameters.V, v) {
			found_sym9 = true
			break
		}
	}

	if !found_sym9 {
		t.Error("FakeJWT.Validate not called with expected parameters")
	}
}

// ValidateCalledOnceWith returns true if FakeJWT.Validate was called exactly once with the given values
func (f_sym10 *FakeJWT) ValidateCalledOnceWith(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) bool {
	var count_sym10 int
	for _, call_sym10 := range f_sym10.ValidateCalls {
		if reflect.DeepEqual(call_sym10.Parameters.Key, key) && reflect.DeepEqual(call_sym10.Parameters.Method, method) && reflect.DeepEqual(call_sym10.Parameters.V, v) {
			count_sym10++
		}
	}

	return count_sym10 == 1
}

// AssertValidateCalledOnceWith calls t.Error if FakeJWT.Validate was not called exactly once with the given values
func (f_sym11 *FakeJWT) AssertValidateCalledOnceWith(t JWTTestingT, key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) {
	t.Helper()
	var count_sym11 int
	for _, call_sym11 := range f_sym11.ValidateCalls {
		if reflect.DeepEqual(call_sym11.Parameters.Key, key) && reflect.DeepEqual(call_sym11.Parameters.Method, method) && reflect.DeepEqual(call_sym11.Parameters.V, v) {
			count_sym11++
		}
	}

	if count_sym11 != 1 {
		t.Errorf("FakeJWT.Validate called %d times with expected parameters, expected one", count_sym11)
	}
}

// ValidateResultsForCall returns the result values for the first call to FakeJWT.Validate with the given values
func (f_sym12 *FakeJWT) ValidateResultsForCall(key interface{}, method crypto.SigningMethod, v ...*jwt.Validator) (ident1 error, found_sym12 bool) {
	for _, call_sym12 := range f_sym12.ValidateCalls {
		if reflect.DeepEqual(call_sym12.Parameters.Key, key) && reflect.DeepEqual(call_sym12.Parameters.Method, method) && reflect.DeepEqual(call_sym12.Parameters.V, v) {
			ident1 = call_sym12.Results.Ident1
			found_sym12 = true
			break
		}
	}

	return
}

func (f_sym13 *FakeJWT) Serialize(key interface{}) (ident1 []byte, ident2 error) {
	if f_sym13.SerializeHook == nil {
		panic("JWT.Serialize() called but FakeJWT.SerializeHook is nil")
	}

	invocation_sym13 := new(JWTSerializeInvocation)
	f_sym13.SerializeCalls = append(f_sym13.SerializeCalls, invocation_sym13)

	invocation_sym13.Parameters.Key = key

	ident1, ident2 = f_sym13.SerializeHook(key)

	invocation_sym13.Results.Ident1 = ident1
	invocation_sym13.Results.Ident2 = ident2

	return
}

// SetSerializeStub configures JWT.Serialize to always return the given values
func (f_sym14 *FakeJWT) SetSerializeStub(ident1 []byte, ident2 error) {
	f_sym14.SerializeHook = func(interface{}) ([]byte, error) {
		return ident1, ident2
	}
}

// SetSerializeInvocation configures JWT.Serialize to return the given results when called with the given parameters
// If no match is found for an invocation the result(s) of the fallback function are returned
func (f_sym15 *FakeJWT) SetSerializeInvocation(calls_sym15 []*JWTSerializeInvocation, fallback_sym15 func() ([]byte, error)) {
	f_sym15.SerializeHook = func(key interface{}) (ident1 []byte, ident2 error) {
		for _, call_sym15 := range calls_sym15 {
			if reflect.DeepEqual(call_sym15.Parameters.Key, key) {
				ident1 = call_sym15.Results.Ident1
				ident2 = call_sym15.Results.Ident2

				return
			}
		}

		return fallback_sym15()
	}
}

// SerializeCalled returns true if FakeJWT.Serialize was called
func (f *FakeJWT) SerializeCalled() bool {
	return len(f.SerializeCalls) != 0
}

// AssertSerializeCalled calls t.Error if FakeJWT.Serialize was not called
func (f *FakeJWT) AssertSerializeCalled(t JWTTestingT) {
	t.Helper()
	if len(f.SerializeCalls) == 0 {
		t.Error("FakeJWT.Serialize not called, expected at least one")
	}
}

// SerializeNotCalled returns true if FakeJWT.Serialize was not called
func (f *FakeJWT) SerializeNotCalled() bool {
	return len(f.SerializeCalls) == 0
}

// AssertSerializeNotCalled calls t.Error if FakeJWT.Serialize was called
func (f *FakeJWT) AssertSerializeNotCalled(t JWTTestingT) {
	t.Helper()
	if len(f.SerializeCalls) != 0 {
		t.Error("FakeJWT.Serialize called, expected none")
	}
}

// SerializeCalledOnce returns true if FakeJWT.Serialize was called exactly once
func (f *FakeJWT) SerializeCalledOnce() bool {
	return len(f.SerializeCalls) == 1
}

// AssertSerializeCalledOnce calls t.Error if FakeJWT.Serialize was not called exactly once
func (f *FakeJWT) AssertSerializeCalledOnce(t JWTTestingT) {
	t.Helper()
	if len(f.SerializeCalls) != 1 {
		t.Errorf("FakeJWT.Serialize called %d times, expected 1", len(f.SerializeCalls))
	}
}

// SerializeCalledN returns true if FakeJWT.Serialize was called at least n times
func (f *FakeJWT) SerializeCalledN(n int) bool {
	return len(f.SerializeCalls) >= n
}

// AssertSerializeCalledN calls t.Error if FakeJWT.Serialize was called less than n times
func (f *FakeJWT) AssertSerializeCalledN(t JWTTestingT, n int) {
	t.Helper()
	if len(f.SerializeCalls) < n {
		t.Errorf("FakeJWT.Serialize called %d times, expected >= %d", len(f.SerializeCalls), n)
	}
}

// SerializeCalledWith returns true if FakeJWT.Serialize was called with the given values
func (f_sym16 *FakeJWT) SerializeCalledWith(key interface{}) bool {
	for _, call_sym16 := range f_sym16.SerializeCalls {
		if reflect.DeepEqual(call_sym16.Parameters.Key, key) {
			return true
		}
	}

	return false
}

// AssertSerializeCalledWith calls t.Error if FakeJWT.Serialize was not called with the given values
func (f_sym17 *FakeJWT) AssertSerializeCalledWith(t JWTTestingT, key interface{}) {
	t.Helper()
	var found_sym17 bool
	for _, call_sym17 := range f_sym17.SerializeCalls {
		if reflect.DeepEqual(call_sym17.Parameters.Key, key) {
			found_sym17 = true
			break
		}
	}

	if !found_sym17 {
		t.Error("FakeJWT.Serialize not called with expected parameters")
	}
}

// SerializeCalledOnceWith returns true if FakeJWT.Serialize was called exactly once with the given values
func (f_sym18 *FakeJWT) SerializeCalledOnceWith(key interface{}) bool {
	var count_sym18 int
	for _, call_sym18 := range f_sym18.SerializeCalls {
		if reflect.DeepEqual(call_sym18.Parameters.Key, key) {
			count_sym18++
		}
	}

	return count_sym18 == 1
}

// AssertSerializeCalledOnceWith calls t.Error if FakeJWT.Serialize was not called exactly once with the given values
func (f_sym19 *FakeJWT) AssertSerializeCalledOnceWith(t JWTTestingT, key interface{}) {
	t.Helper()
	var count_sym19 int
	for _, call_sym19 := range f_sym19.SerializeCalls {
		if reflect.DeepEqual(call_sym19.Parameters.Key, key) {
			count_sym19++
		}
	}

	if count_sym19 != 1 {
		t.Errorf("FakeJWT.Serialize called %d times with expected parameters, expected one", count_sym19)
	}
}

// SerializeResultsForCall returns the result values for the first call to FakeJWT.Serialize with the given values
func (f_sym20 *FakeJWT) SerializeResultsForCall(key interface{}) (ident1 []byte, ident2 error, found_sym20 bool) {
	for _, call_sym20 := range f_sym20.SerializeCalls {
		if reflect.DeepEqual(call_sym20.Parameters.Key, key) {
			ident1 = call_sym20.Results.Ident1
			ident2 = call_sym20.Results.Ident2
			found_sym20 = true
			break
		}
	}

	return
}
