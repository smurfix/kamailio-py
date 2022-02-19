===================
Kamailio for Python
===================

This Python package attempts to provide an API to Kamailio scripting.

While Kamailio has a Python scripting interface, its way of interacting
with the core is shaped by its ad-hoc scripting language, which is decidedly
not Python.

This code allows you to access its data in a more Pythonic manner.

------------
Installation
------------

Install Kamailio, Python, and this module as usual.

Add this to your ``kamailio.cfg``:

        loadmodule "app_python3.so"
        modparam("app_python3", "load", "/etc/kamailio/router.py")
        cfgengine "python"

Copy one of the sample routing scripts from our ``sample`` directory
to ``/etc/kamailio/router.py``.
