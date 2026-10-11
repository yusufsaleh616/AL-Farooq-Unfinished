"""Admin tasks you run on the server machine (trusted, so no login needed).

    python manage.py list-users
    python manage.py list-devices
    python manage.py verify-email   USERNAME
    python manage.py set-role       USERNAME user|admin|super_admin
    python manage.py approve-device DEVICE_ID

This is how the very first super admin gets created: register on the website,
verify the email, run set-role, enrol a device from the desktop app, then run
approve-device. After that the dashboard can approve more devices.
"""
import argparse
import sys

from app.database import Base, SessionLocal, engine
from app.models import Device, User


def main():
    Base.metadata.create_all(bind=engine)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-users")
    sub.add_parser("list-devices")
    sub.add_parser("verify-email").add_argument("username")
    p = sub.add_parser("set-role")
    p.add_argument("username")
    p.add_argument("role", choices=["user", "admin", "super_admin"])
    sub.add_parser("approve-device").add_argument("device_id", type=int)
    args = parser.parse_args()

    db = SessionLocal()
    if args.cmd == "list-users":
        for u in db.query(User).order_by(User.id):
            print(f"{u.id:3} {u.username:20} {u.role:12} verified={u.email_verified} {u.email}")
    elif args.cmd == "list-devices":
        for d in db.query(Device).order_by(Device.id):
            print(f"{d.id:3} user_id={d.user_id} status={d.status}")
    elif args.cmd == "verify-email":
        user = db.query(User).filter_by(username=args.username.lower()).first()
        if not user:
            sys.exit("no such user")
        user.email_verified = True
        db.commit()
        print("email marked as verified")
    elif args.cmd == "set-role":
        user = db.query(User).filter_by(username=args.username.lower()).first()
        if not user:
            sys.exit("no such user")
        user.role = args.role
        db.commit()
        print(f"{user.username} is now {user.role}")
    elif args.cmd == "approve-device":
        device = db.query(Device).filter_by(id=args.device_id).first()
        if not device:
            sys.exit("no such device")
        device.status = "approved"
        db.commit()
        print("device approved")
    db.close()


if __name__ == "__main__":
    main()
