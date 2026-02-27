# IDLReflectedAttribute SPEC

## DOMString
If a reflecting IDL attribute is a DOMString attribute whose content
attribute is an enumerated attribute, and the IDL attribute is limited
to only known values, then, on getting, the IDL attribute must return
the conforming value associated with the state the attribute is in
(in its canonical case), if any, or the empty string if the attribute
is in a state that has no associated keyword value or if the attribute
is not in a defined state (e.g. the attribute is missing and there is
no missing value default). On setting, the content attribute must be
set to the specified new value.

If a reflecting IDL attribute is a nullable DOMString attribute whose
content attribute is an enumerated attribute, then, on getting, if the
corresponding content attribute is in its missing value default then the
IDL attribute must return null, otherwise, the IDL attribute must return
the conforming value associated with the state the attribute is in
(in its canonical case). On setting, if the new value is null, the content
attribute must be removed, and otherwise, the content attribute must be set
to the specified new value.

## Note
There are HTML Elements whose default values are a function
of the Element. Therefore this spec must allow for default
values to be specified as callback functions!

In some cases, e.g. 'tabIndex' attribute of an HTML Element,
the value of the attribute is *always* computed from the Element,
and so the 'default' function is actually just computing the
value!
