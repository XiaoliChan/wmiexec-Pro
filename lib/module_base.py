class ModuleBase:
    """Base class for wmiexec-pro modules.

    Each module should define:
        name (str): subparser command name (e.g. "smb-takeover")
        description (str): help text for the subparser

    And implement:
        register_parser(subparsers): add argparse subparser, return the parser
        run(iWbemLevel1Login, dcom, options, **kwargs): execute module logic
    """
    name = ""
    description = ""

    @staticmethod
    def register_parser(subparsers):
        """Register argparse subparser for this module. Return the parser."""
        raise NotImplementedError

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        """Execute the module.

        kwargs may include:
            addr (str): target address
            username (str): authenticated username
            codec (str): output codec
        """
        raise NotImplementedError
