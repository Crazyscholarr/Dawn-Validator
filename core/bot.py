from datetime import datetime, timedelta
from typing import Tuple, Any, Optional, Literal

import pytz
from loguru import logger
from loader import config, file_operations, captcha_solver
from models import Account, OperationResult, StatisticData

from .api import DawnExtensionAPI
from utils import EmailValidator, LinkExtractor
from database import Accounts
from .exceptions.base import APIError, SessionRateLimited, CaptchaSolvingFailed, APIErrorType


class Bot(DawnExtensionAPI):
    def __init__(self, account: Account):
        super().__init__(account)

    async def clear_account_and_session(self) -> None:
        if await Accounts.get_account(email=self.account_data.email):
            await Accounts.delete_account(email=self.account_data.email)
        self.session = self._create_session()

    @staticmethod
    async def handle_invalid_account(email: str, password: str, reason: Literal["unverified", "banned", "unregistered"]) -> None:
        if reason == "unverified":
            logger.error(f"Account: {email} |Email chưa được xác minh, hãy chạy mô-đun xác minh lại | Đã xóa khỏi danh sách")
            await file_operations.export_unverified_email(email, password)

        elif reason == "banned":
            logger.error(f"Account: {email} |Tài khoản bị cấm | Đã xóa khỏi danh sách")
            await file_operations.export_banned_email(email, password)

        elif reason == "unregistered":
            logger.error(f"Account: {email} | Tài khoản chưa được đăng ký | Đã xóa khỏi danh sách")
            await file_operations.export_unregistered_email(email, password)

        for account in config.accounts_to_farm:
            if account.email == email:
                config.accounts_to_farm.remove(account)

    @staticmethod
    def get_sleep_until(blocked: bool = False) -> datetime:
        duration = (
            timedelta(minutes=10)
            if blocked
            else timedelta(seconds=config.keepalive_interval)
        )
        return datetime.now(pytz.UTC) + duration


    async def _validate_email(self) -> dict:
        if config.redirect_settings.enabled:
            result = await EmailValidator(
                config.redirect_settings.imap_server,
                config.redirect_settings.email,
                config.redirect_settings.password
            ).validate(None if config.redirect_settings.use_proxy is False else self.account_data.proxy)
        else:
            result = await EmailValidator(
                self.account_data.imap_server,
                self.account_data.email,
                self.account_data.password
            ).validate(None if config.use_proxy_for_imap is False else self.account_data.proxy)

        return result


    async def _extract_link(self) -> dict:
        if config.redirect_settings.enabled:
            confirm_url = await LinkExtractor(
                imap_server=config.redirect_settings.imap_server,
                email=config.redirect_settings.email,
                password=config.redirect_settings.password,
                redirect_email=self.account_data.email
            ).extract_link(None if config.redirect_settings.use_proxy is False else self.account_data.proxy)
        else:
            confirm_url = await LinkExtractor(
                imap_server=self.account_data.imap_server,
                email=self.account_data.email,
                password=self.account_data.password,
            ).extract_link(None if config.redirect_settings.use_proxy is False else self.account_data.proxy)

        return confirm_url

    async def get_captcha_data(
            self,
            captcha_type: Literal["image", "turnistale"],
            max_attempts: int = 5
    ) -> Tuple[str, Any, Optional[Any]] | str:
        async def handle_image_captcha() -> Tuple[str, str, Optional[Any]]:
            puzzle_id = await self.get_puzzle_id()
            image = await self.get_puzzle_image(puzzle_id)

            logger.info(f"Account: {self.account_data.email} |Có hình ảnh câu đố, đang giải...")
            answer, solved, *rest = await captcha_solver.solve_image(image)

            if solved and len(answer) == 6:
                logger.success(f"Account: {self.account_data.email} | Câu đố đã giải: {answer}")
                return puzzle_id, answer, rest[0] if rest else None

            if len(answer) != 6 and rest:
                await captcha_solver.report_bad(rest[0])

            logger.error(f"Account: {self.account_data.email} | Không giải được câu đố:  {answer}")
            raise ValueError(f"Không giải được câu đố: {answer}")

        async def handle_turnistale_captcha() -> str:
            logger.info(f"Account: {self.account_data.email} | Solving Cloudflare challenge...")
            answer, solved, *rest = await captcha_solver.solve_turnistale()

            if solved:
                logger.success(f"Account: {self.account_data.email} | Giải quyết thách thức của Cloudflare")
                return answer

            logger.error(f"Account: {self.account_data.email} | Không giải quyết được thử thách của Cloudflare: {answer}")
            raise ValueError(f"Không giải quyết được thử thách của Cloudflare: {answer}")

        handler = handle_image_captcha if captcha_type == "image" else handle_turnistale_captcha
        for attempt in range(max_attempts):
            try:
                return await handler()
            except SessionRateLimited:
                raise
            except Exception as e:
                logger.error(
                    f"Account: {self.account_data.email} | Đã xảy ra lỗi khi giải captcha ({captcha_type}): {str(e)} | Đang thử lại..."
                )
                if attempt == max_attempts - 1:
                    raise CaptchaSolvingFailed(f"Không giải được captcha sau  {max_attempts}  lần thử")

    async def process_reverify_email(self, link_sent: bool = False) -> OperationResult:
        task_id = None

        try:
            result = await self._validate_email()
            if not result["status"]:
                logger.error(f"Account: {self.account_data.email} | Email không hợp lệ: {result['data']}")
                return OperationResult(
                    identifier=self.account_data.email,
                    data=self.account_data.password,
                    status=False,
                )

            logger.info(f"Account: {self.account_data.email} | Re-verifying email...")
            if not self.account_data.appid:
                self.account_data.appid = await self.get_app_id()

            puzzle_id, answer, task_id = await self.get_captcha_data("image")
            if not link_sent:
                await self.resend_verify_link(puzzle_id, answer)
                logger.info(f"Account: {self.account_data.email} | Gửi lại email xác minh thành công, đang chờ email...")
                link_sent = True

            confirm_url = await self._extract_link()
            if not confirm_url["status"]:
                logger.error(f"Account: {self.account_data.email} | Không tìm thấy liên kết xác nhận: {confirm_url['data']}")
                return OperationResult(
                    identifier=self.account_data.email,
                    data=self.account_data.password,
                    status=False,
                )

            logger.success(
                f"Account: {self.account_data.email} | Đã tìm thấy liên kết, xác nhận email..."
            )

            try:
                key = confirm_url["data"].split("key=")[1]
            except IndexError:
                response = await self.clear_request(confirm_url["data"])
                key = response.url.split("key=")[1]

            cloudflare_token = await self.get_captcha_data("turnistale")
            await self.verify_registration(key, cloudflare_token)

            logger.success(f"Email đã được xác minh thành công")
            return OperationResult(
                identifier=self.account_data.email,
                data=self.account_data.password,
                status=True,
            )

        except APIError as error:
            match error.error_type:
                case APIErrorType.INCORRECT_CAPTCHA:
                    logger.warning(f"Account: {self.account_data.email} | Trả lời captcha không đúng, đang giải quyết lại...")
                    if task_id:
                        await captcha_solver.report_bad(task_id)
                    return await self.process_reverify_email(link_sent=link_sent)

                case APIErrorType.EMAIL_EXISTS:
                    logger.warning(f"Account: {self.account_data.email} | Email đã tồn tại")

                case APIErrorType.CAPTCHA_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Captcha đã hết hạn, đang giải quyết lại...")
                    return await self.process_reverify_email(link_sent=link_sent)

                case APIErrorType.SESSION_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Phiên đã hết hạn, đăng nhập lại...")
                    await self.clear_account_and_session()
                    return await self.process_reverify_email(link_sent=link_sent)

                case APIErrorType.INVALID_CAPTCHA_TOKEN:
                    logger.warning(f"Account: {self.account_data.email} | Mã thông báo captcha không hợp lệ, đang giải quyết lại...")
                    return await self.process_reverify_email(link_sent=link_sent)

                case _:
                    logger.error(f"Account: {self.account_data.email} | Không thể xác minh lại email: {error}")

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Không xác minh lại được email: {error}"
            )

        return OperationResult(
            identifier=self.account_data.email,
            data=self.account_data.password,
            status=False,
        )


    async def process_registration(self) -> OperationResult:
        task_id = None

        try:
            result = await self._validate_email()
            if not result["status"]:
                logger.error(f"Account: {self.account_data.email} |Email không hợp lệ: {result['data']}")
                return OperationResult(
                    identifier=self.account_data.email,
                    data=self.account_data.password,
                    status=False,
                )

            logger.info(f"Account: {self.account_data.email} | Đăng ký...")
            captcha_token = await self.get_captcha_data("turnistale")

            await self.register(captcha_token)
            logger.info(
                f"Account: {self.account_data.email} | Đã đăng ký, đang chờ email..."
            )

            confirm_url = await self._extract_link()
            if not confirm_url["status"]:
                logger.error(f"Account: {self.account_data.email} | Không tìm thấy liên kết xác nhận: {confirm_url['data']}")
                return OperationResult(
                    identifier=self.account_data.email,
                    data=self.account_data.password,
                    status=False,
                )

            logger.success(
                f"Account: {self.account_data.email} | Đã tìm thấy liên kết, xác nhận đăng ký..."
            )

            try:
                key = confirm_url["data"].split("key=")[1]
            except IndexError:
                response = await self.clear_request(confirm_url["data"])
                key = response.url.split("key=")[1]

            cloudflare_token = await self.get_captcha_data("turnistale")
            await self.verify_registration(key, cloudflare_token)

            logger.success(f"Đã xác minh và hoàn tất đăng ký")
            return OperationResult(
                identifier=self.account_data.email,
                data=self.account_data.password,
                status=True,
            )


        except APIError as error:
            match error.error_type:
                case APIErrorType.INCORRECT_CAPTCHA:
                    logger.warning(f"Account: {self.account_data.email} | Trả lời captcha không đúng, cần giải quyết lại...")
                    if task_id:
                        await captcha_solver.report_bad(task_id)
                    return await self.process_registration()

                case APIErrorType.EMAIL_EXISTS:
                    logger.warning(f"Account: {self.account_data.email} | Email đã tồn tại")

                case APIErrorType.CAPTCHA_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Captcha đã hết hạn, đang giải quyết lại...")
                    return await self.process_registration()

                case APIErrorType.INVALID_CAPTCHA_TOKEN:
                    logger.warning(f"Account: {self.account_data.email} | Mã thông báo captcha không hợp lệ, đang giải quyết lại...")
                    return await self.process_registration()

                case _:
                    if "Something went wrong" in error.error_message:
                        logger.warning(f"Account: {self.account_data.email} | Tên miền email có khả năng cao nhất <{self.account_data.email.split('@')[1]}> bị banned")
                    else:
                        logger.error(f"Account: {self.account_data.email} | Không đăng ký được: {error}")

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Failed to register: {error}"
            )

        return OperationResult(
            identifier=self.account_data.email,
            data=self.account_data.password,
            status=False,
        )

    async def process_farming(self) -> None:
        try:
            db_account_data = await Accounts.get_account(email=self.account_data.email)

            if db_account_data and db_account_data.session_blocked_until:
                if await self.handle_sleep(db_account_data.session_blocked_until):
                    return

            if not db_account_data or not db_account_data.auth_token:
                if not await self.login_new_account():
                    return

            elif not await self.handle_existing_account(db_account_data):
                return

            await self.perform_farming_actions()

        except SessionRateLimited:
            await self.handle_session_blocked()

        except APIError as error:
            match error.error_type:
                case APIErrorType.UNVERIFIED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unverified")

                case APIErrorType.BANNED:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")

                case APIErrorType.UNREGISTERED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unregistered")

                case APIErrorType.SESSION_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Phiên đã hết hạn, đăng nhập lại...")
                    await self.clear_account_and_session()
                    return await self.process_farming()

                case _:
                    if "Có gì đó không ổn" in error.error_message:
                        await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")
                    else:
                        logger.error(f"Account: {self.account_data.email} | Không thể canh tác: {error}")


        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Không thể canh tác: {error}"
            )

        return

    async def process_get_user_info(self) -> StatisticData:
        try:
            db_account_data = await Accounts.get_account(email=self.account_data.email)

            if not db_account_data or not db_account_data.auth_token:
                if not await self.login_new_account():
                    return StatisticData(
                        success=False, referralPoint=None, rewardPoint=None
                    )

            elif not await self.handle_existing_account(db_account_data, verify_sleep=False):
                return StatisticData(
                    success=False, referralPoint=None, rewardPoint=None
                )

            user_info = await self.user_info()
            logger.success(
                f"Account: {self.account_data.email} | Đã lấy được thông tin người dùng thành công"
            )
            return StatisticData(
                success=True,
                referralPoint=user_info["referralPoint"],
                rewardPoint=user_info["rewardPoint"],
            )

        except SessionRateLimited:
            await self.handle_session_blocked()

        except APIError as error:
            match error.error_type:
                case APIErrorType.UNVERIFIED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unverified")

                case APIErrorType.BANNED:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")

                case APIErrorType.UNREGISTERED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unregistered")

                case APIErrorType.SESSION_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Phiên đã hết hạn, đăng nhập lại...")
                    await self.clear_account_and_session()
                    return await self.process_get_user_info()

                case _:
                    if "Something went wrong" in error.error_message:
                        await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")
                    else:
                        logger.error(
                            f"Account: {self.account_data.email} | Không lấy được thông tin người dùng: {error}"
                        )

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Không lấy được thông tin người dùng: {error}"
            )

        return StatisticData(success=False, referralPoint=None, rewardPoint=None)

    async def process_complete_tasks(self) -> OperationResult:
        try:
            db_account_data = await Accounts.get_account(email=self.account_data.email)
            if db_account_data is None:
                if not await self.login_new_account():
                    return OperationResult(
                        identifier=self.account_data.email,
                        data=self.account_data.password,
                        status=False,
                    )
            else:
                await self.handle_existing_account(db_account_data, verify_sleep=False)

            logger.info(f"Account: {self.account_data.email} | Đang hoàn thành nhiệm vụ... | Có thể mất một lúc")
            await self.complete_tasks()

            logger.success(
                f"Account: {self.account_data.email} |Nhiệm vụ đã hoàn thành thành công"
            )
            return OperationResult(
                identifier=self.account_data.email,
                data=self.account_data.password,
                status=True,
            )

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Không hoàn thành được nhiệm vụ: {error}"
            )
            return OperationResult(
                identifier=self.account_data.email,
                data=self.account_data.password,
                status=False,
            )

    async def login_new_account(self):
        task_id = None

        try:
            logger.info(f"Account: {self.account_data.email} | Logging in...")
            self.account_data.appid = await self.get_app_id()
            puzzle_id, answer, task_id = await self.get_captcha_data("image")

            self.account_data.auth_token = await self.login(puzzle_id, answer)
            logger.info(f"Account: {self.account_data.email} | Successfully logged in")

            await Accounts.create_account(email=self.account_data.email, app_id=self.account_data.appid, auth_token=self.account_data.auth_token)
            return True

        except APIError as error:
            match error.error_type:
                case APIErrorType.INCORRECT_CAPTCHA:
                    logger.warning(f"Account: {self.account_data.email} | Trả lời captcha không đúng, giải quyết lại...")
                    if task_id:
                        await captcha_solver.report_bad(task_id)
                    return await self.login_new_account()

                case APIErrorType.UNVERIFIED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unverified")
                    return False

                case APIErrorType.UNREGISTERED_EMAIL:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "unregistered")
                    return False

                case APIErrorType.BANNED:
                    await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")
                    return False

                case APIErrorType.CAPTCHA_EXPIRED:
                    logger.warning(f"Account: {self.account_data.email} | Captcha đã hết hạn, đang giải quyết lại...")
                    return await self.login_new_account()

                case _:
                    if "Something went wrong" in error.error_message:
                        await self.handle_invalid_account(self.account_data.email, self.account_data.password, "banned")
                    else:
                        logger.error(f"Account: {self.account_data.email} | Không thể đăng nhập rồi.... {error}")

                    return False

        except CaptchaSolvingFailed:
            sleep_until = self.get_sleep_until()
            await Accounts.set_sleep_until(self.account_data.email, sleep_until)
            logger.error(
                f"Account: {self.account_data.email} | Không giải được captcha sau 5 lần thử, đang ngủ..."
            )
            return False

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Đăng nhập không thành công: {error}"
            )
            return False

    async def handle_existing_account(self, db_account_data, verify_sleep: bool = True) -> bool | None:
        if verify_sleep:
            if db_account_data.sleep_until and await self.handle_sleep(
                db_account_data.sleep_until
            ):
                return False

        status, result = await self.verify_session()
        if not status:
            logger.warning(
                f"Account: {self.account_data.email} | Phiên không hợp lệ, hãy đăng nhập lại: {result}"
            )
            await self.clear_account_and_session()
            return await self.process_farming()

        logger.info(f"Account: {self.account_data.email} | Sử dụng phiên hiện có")
        return True

    async def handle_session_blocked(self):
        await self.clear_account_and_session()
        logger.error(
            f"Account: {self.account_data.email} | Tỷ lệ phiên giới hạn | Ngủ..."
        )
        sleep_until = self.get_sleep_until(blocked=True)
        await Accounts.set_session_blocked_until(email=self.account_data.email, session_blocked_until=sleep_until, app_id=self.account_data.appid)

    async def handle_sleep(self, sleep_until):
        current_time = datetime.now(pytz.UTC)
        sleep_until = sleep_until.replace(tzinfo=pytz.UTC)

        if sleep_until > current_time:
            sleep_duration = (sleep_until - current_time).total_seconds()
            logger.debug(
                f"Account: {self.account_data.email} | NGHỈ NGƠI   (thời lượng: {sleep_duration:.2f} seconds)"
            )
            return True

        return False

    async def perform_farming_actions(self):
        try:
            await self.keepalive()
            logger.success(
                f"Account: {self.account_data.email} | Đã gửi yêu cầu duy trì kết nối thành công"
            )

            user_info = await self.user_info()
            logger.info(
                f"Account: {self.account_data.email} | Đã gửi yêu cầu duy trì kết nối {user_info['rewardPoint']['points']}"
            )

        except Exception as error:
            logger.error(
                f"Account: {self.account_data.email} | Không thực hiện được hành động canh tác: {error}"
            )

        finally:
            new_sleep_until = self.get_sleep_until()
            await Accounts.set_sleep_until(
                email=self.account_data.email, sleep_until=new_sleep_until
            )

    async def close_session(self):
        try:
            await self.session.close()
        except Exception as error:
            logger.debug(
                f"Account: {self.account_data.email} | Không thể đóng phiên:  {error}"
            )
