import RowCommentsSidebar from '@baserow_premium/components/row_comments/RowCommentsSidebar'
import { DatabaseApplicationType } from '@baserow/modules/database/applicationTypes'
import GridViewRowExpandButtonWithCommentCount from '@baserow_premium/components/row_comments/GridViewRowExpandButtonWithCommentCount'

export class PremiumDatabaseApplicationType extends DatabaseApplicationType {
  getRowEditModalRightSidebarComponent(table) {
    return this.app.$hasPermission('database.table.list_comments', table)
      ? RowCommentsSidebar
      : null
  }

  getRowExpandButtonComponent() {
    return GridViewRowExpandButtonWithCommentCount
  }
}
