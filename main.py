import argparse
import sys
import multiprocessing
from src.core.engine import Engine
from src.utils.logger import Logger
from src.utils.banner import Banner

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Zoro Toolkit - Domain Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-d', '--domain',
        help='Target domain to analyze',
        required=True
    )

    parser.add_argument(
        '-w', '--workers',
        help='Number of worker processes',
        type=int,
        default=min(4, multiprocessing.cpu_count())
    )

    return parser.parse_args()

def main():
    logger = Logger(__name__)
    banner = Banner()

    try:
        args = parse_arguments()

        # Show banner
        banner.show_banner()

        logger.info(f"[*] Target domain: {args.domain}")
        logger.info(f"[*] Using {args.workers} workers")

        # Initialize and run the engine
        engine = Engine(args.domain, workers=args.workers)
        results = engine.run()

        if results:
            logger.info("[+] Reconnaissance completed successfully")
        else:
            logger.error("[-] No results found")

    except KeyboardInterrupt:
        logger.error("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    multiprocessing.set_start_method('spawn', force=True)
    main()